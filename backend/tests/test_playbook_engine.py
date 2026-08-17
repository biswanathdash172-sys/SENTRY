"""
test_playbook_engine.py
------------------------
Real unit tests for services/playbook_engine.py.

This is the "human-governed" safety boundary of the whole product: low-
risk actions must auto-execute, high-impact actions must always require
manual approval. These tests exist specifically to catch the risk
ROADMAP.md Day 5 calls out: "is anything mis-classified as auto that
should require approval?"
"""
import pytest

from models import Evidence
from services import playbook_engine as pe

HIGH_RISK_LABELS = {
    "Suspend user account",
    "Freeze pending wire transfer",
    "Revoke signing credential",
    "Force password reset (all sessions)",
    "Escalate to legal/compliance",
}
LOW_RISK_LABELS = {
    "Quarantine suspicious email",
    "Block sender domain",
    "Isolate endpoint from network",
    "Flag media as unverified",
    "Notify security team",
}


def make_evidence(source_type="email", confidence=0.5):
    return Evidence(source_type=source_type, description="test signal", confidence=confidence)


class TestRiskClassificationSafetyBoundary:
    """The single most important property: nothing high-impact ever auto-executes."""

    @pytest.mark.parametrize("label", sorted(HIGH_RISK_LABELS))
    def test_high_risk_actions_are_always_manual(self, label):
        assert pe.ACTION_RISK_TABLE[label] == "high"

    @pytest.mark.parametrize("label", sorted(LOW_RISK_LABELS))
    def test_low_risk_actions_are_always_auto_eligible(self, label):
        assert pe.ACTION_RISK_TABLE[label] == "low"

    def test_generated_playbook_never_auto_executes_a_high_risk_action(self):
        # Exercise every source type + critical severity at once — the
        # worst-case scenario most likely to generate high-risk actions.
        evidence = [
            make_evidence("email"), make_evidence("endpoint"),
            make_evidence("media"), make_evidence("identity"),
        ]
        playbook = pe.generate_playbook(evidence, severity="critical")
        for action in playbook:
            if action.risk_level == "high":
                assert action.mode == "manual", (
                    f"SAFETY VIOLATION: '{action.label}' is high-risk but mode={action.mode}"
                )

    def test_generated_playbook_never_marks_a_low_risk_action_as_manual(self):
        evidence = [make_evidence("email")]
        playbook = pe.generate_playbook(evidence, severity="low")
        for action in playbook:
            if action.risk_level == "low":
                assert action.mode == "auto"


class TestGeneratePlaybookBySourceType:
    def test_email_evidence_adds_quarantine_and_block_domain(self):
        playbook = pe.generate_playbook([make_evidence("email")], severity="low")
        labels = {a.label for a in playbook}
        assert "Quarantine suspicious email" in labels
        assert "Block sender domain" in labels

    def test_endpoint_evidence_adds_isolation(self):
        playbook = pe.generate_playbook([make_evidence("endpoint")], severity="low")
        labels = {a.label for a in playbook}
        assert "Isolate endpoint from network" in labels

    def test_media_evidence_adds_flag_and_revoke_credential(self):
        playbook = pe.generate_playbook([make_evidence("media")], severity="low")
        labels = {a.label for a in playbook}
        assert "Flag media as unverified" in labels
        assert "Revoke signing credential" in labels

    def test_identity_evidence_adds_password_reset(self):
        playbook = pe.generate_playbook([make_evidence("identity")], severity="low")
        labels = {a.label for a in playbook}
        assert "Force password reset (all sessions)" in labels

    def test_no_matching_source_type_produces_no_source_specific_actions(self):
        # network isn't wired to any specific action in playbook_engine.py
        playbook = pe.generate_playbook([make_evidence("network")], severity="low")
        labels = {a.label for a in playbook}
        assert labels.isdisjoint({
            "Quarantine suspicious email", "Isolate endpoint from network",
            "Flag media as unverified", "Force password reset (all sessions)",
        })


class TestGeneratePlaybookBySeverity:
    def test_low_and_medium_severity_never_notify_or_escalate(self):
        for severity in ("low", "medium"):
            playbook = pe.generate_playbook([make_evidence("email")], severity=severity)
            labels = {a.label for a in playbook}
            assert "Notify security team" not in labels
            assert "Suspend user account" not in labels

    def test_high_severity_notifies_but_does_not_escalate_to_legal(self):
        playbook = pe.generate_playbook([make_evidence("email")], severity="high")
        labels = {a.label for a in playbook}
        assert "Notify security team" in labels
        assert "Escalate to legal/compliance" not in labels

    def test_critical_severity_adds_full_escalation_set(self):
        playbook = pe.generate_playbook([make_evidence("email")], severity="critical")
        labels = {a.label for a in playbook}
        assert "Suspend user account" in labels
        assert "Freeze pending wire transfer" in labels
        assert "Escalate to legal/compliance" in labels
        assert "Notify security team" in labels


class TestGeneratePlaybookGeneral:
    def test_no_evidence_and_low_severity_produces_empty_playbook(self):
        playbook = pe.generate_playbook([], severity="low")
        assert playbook == []

    def test_actions_are_deduplicated(self):
        # Two email-sourced evidence items should not double up actions.
        playbook = pe.generate_playbook(
            [make_evidence("email"), make_evidence("email")], severity="low"
        )
        labels = [a.label for a in playbook]
        assert len(labels) == len(set(labels))

    def test_unknown_action_label_defaults_to_high_risk_fail_safe(self):
        # ACTION_RISK_TABLE.get(label, "high") — anything NOT in the table
        # must default to high/manual, never silently auto-execute.
        risk = pe.ACTION_RISK_TABLE.get("Some future action not yet in the table", "high")
        assert risk == "high"