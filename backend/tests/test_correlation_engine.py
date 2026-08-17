"""
test_correlation_engine.py
---------------------------
Real unit tests for services/correlation_engine.py — no mocks needed,
since the engine is pure/deterministic rules-based logic (no ML, no I/O).

Covers:
  - combined_confidence(): the "independent misses" probability math
  - severity_from_confidence(): the threshold boundaries
  - build_attack_chain(): ordering, formatting, empty-evidence case
  - correlate(): end-to-end shape returned to main.py / _ingest()
"""
import pytest

from models import Evidence
from services import correlation_engine as ce


def make_evidence(source_type="email", description="test signal", confidence=0.5):
    return Evidence(source_type=source_type, description=description, confidence=confidence)


# ---------------------------------------------------------------------------
# combined_confidence
# ---------------------------------------------------------------------------
class TestCombinedConfidence:
    def test_empty_evidence_returns_zero(self):
        assert ce.combined_confidence([]) == 0.0

    def test_single_evidence_returns_its_own_confidence(self):
        ev = [make_evidence(confidence=0.7)]
        assert ce.combined_confidence(ev) == 0.7

    def test_multiple_evidence_increases_combined_confidence(self):
        # Two independent 0.5-confidence signals should combine to MORE
        # than either alone: 1 - (1-0.5)*(1-0.5) = 0.75
        ev = [make_evidence(confidence=0.5), make_evidence(confidence=0.5)]
        assert ce.combined_confidence(ev) == 0.75

    def test_combined_confidence_never_exceeds_one(self):
        ev = [make_evidence(confidence=0.9), make_evidence(confidence=0.95), make_evidence(confidence=0.99)]
        result = ce.combined_confidence(ev)
        assert 0.0 <= result <= 1.0

    def test_confidence_values_are_clamped_to_valid_range(self):
        # Defensive: a caller passing an out-of-range confidence should not
        # blow up the math or produce a value outside [0, 1].
        ev = [make_evidence(confidence=1.5), make_evidence(confidence=-0.3)]
        result = ce.combined_confidence(ev)
        assert 0.0 <= result <= 1.0


# ---------------------------------------------------------------------------
# severity_from_confidence
# ---------------------------------------------------------------------------
class TestSeverityFromConfidence:
    @pytest.mark.parametrize(
        "confidence,expected",
        [
            (0.0, "low"),
            (0.39, "low"),
            (0.4, "medium"),
            (0.64, "medium"),
            (0.65, "high"),
            (0.84, "high"),
            (0.85, "critical"),
            (1.0, "critical"),
        ],
    )
    def test_threshold_boundaries(self, confidence, expected):
        assert ce.severity_from_confidence(confidence) == expected


# ---------------------------------------------------------------------------
# build_attack_chain
# ---------------------------------------------------------------------------
class TestBuildAttackChain:
    def test_no_evidence_returns_placeholder_message(self):
        chain = ce.build_attack_chain([])
        assert chain == ["No evidence attached to this alert yet."]

    def test_chain_has_one_step_per_evidence_plus_conclusion(self):
        ev = [make_evidence(), make_evidence(), make_evidence()]
        chain = ce.build_attack_chain(ev)
        assert len(chain) == len(ev) + 1  # N steps + 1 conclusion line
        assert chain[-1].startswith("Conclusion:")

    def test_steps_are_ordered_by_timestamp(self):
        early = Evidence(source_type="email", description="first", confidence=0.5,
                          timestamp="2024-01-01T00:00:00")
        late = Evidence(source_type="network", description="second", confidence=0.5,
                         timestamp="2024-01-02T00:00:00")
        # Pass in reverse chronological order; output should still be earliest-first.
        chain = ce.build_attack_chain([late, early])
        assert "first" in chain[0]
        assert "second" in chain[1]

    def test_step_includes_source_label_description_and_confidence_pct(self):
        ev = [make_evidence(source_type="media", description="unsigned CFO video", confidence=0.8)]
        chain = ce.build_attack_chain(ev)
        assert "Media authenticity signal" in chain[0]
        assert "unsigned CFO video" in chain[0]
        assert "80%" in chain[0]

    def test_unknown_source_type_falls_back_to_titlecased_label(self):
        # source_type is a Literal in models.py, so construct normally then
        # mutate post-construction to exercise the SOURCE_LABELS.get(...,
        # fallback) branch defensively.
        ev = make_evidence(source_type="email")
        ev.source_type = "custom_feed"
        chain = ce.build_attack_chain([ev])
        assert "Custom_Feed" in chain[0]


# ---------------------------------------------------------------------------
# correlate (end-to-end)
# ---------------------------------------------------------------------------
class TestCorrelate:
    def test_returns_expected_shape(self):
        ev = [make_evidence()]
        result = ce.correlate(ev, title_hint="My Alert")
        assert set(result.keys()) == {"title", "severity", "evidence", "attack_chain"}
        assert result["title"] == "My Alert"
        assert result["evidence"] == ev

    def test_default_title_hint_used_when_not_provided(self):
        result = ce.correlate([make_evidence()])
        assert result["title"] == "Correlated Alert"

    def test_high_confidence_multi_signal_produces_high_or_critical_severity(self):
        # Mirrors the flagship deepfake-wire-fraud demo scenario in main.py.
        ev = [
            make_evidence(source_type="media", description="deepfake CFO video", confidence=0.94),
            make_evidence(source_type="email", description="lookalike domain", confidence=0.68),
            make_evidence(source_type="identity", description="bypasses approval chain", confidence=0.5),
        ]
        result = ce.correlate(ev, title_hint="Likely deepfake-powered wire-fraud attempt")
        assert result["severity"] in ("high", "critical")
        assert len(result["attack_chain"]) == len(ev) + 1

    def test_empty_evidence_produces_low_severity_and_placeholder_chain(self):
        result = ce.correlate([])
        assert result["severity"] == "low"
        assert result["attack_chain"] == ["No evidence attached to this alert yet."]