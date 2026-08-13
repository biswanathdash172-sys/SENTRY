"""
playbook_engine.py
-------------------
Decides recommended response actions for an alert and classifies each as
"auto" (safe, reversible -> executes immediately) or "manual" (high-impact,
hard-to-reverse -> always waits for a human Approve/Deny click).

This is the "human-in-the-loop" guardrail described in EXPLANATION.md §2-3.
A misclassified auto-action is treated as a real bug in this domain
(EXECUTION_PLAN.md stage 10), so the risk table below is intentionally
explicit and conservative rather than inferred by a model.
"""

from typing import List
from models import PlaybookAction, Evidence

# label -> risk_level. Anything not in this table defaults to "high" risk
# (fail-safe: unknown action => require a human).
ACTION_RISK_TABLE = {
    "Quarantine suspicious email": "low",
    "Block sender domain": "low",
    "Isolate endpoint from network": "low",
    "Flag media as unverified": "low",
    "Notify security team": "low",
    "Suspend user account": "high",
    "Freeze pending wire transfer": "high",
    "Revoke signing credential": "high",
    "Force password reset (all sessions)": "high",
    "Escalate to legal/compliance": "high",
}


def _has_source(evidence: List[Evidence], source_type: str) -> bool:
    return any(e.source_type == source_type for e in evidence)


def generate_playbook(evidence: List[Evidence], severity: str) -> List[PlaybookAction]:
    """
    Builds a recommended action list from the evidence mix + severity.
    Rule-based per ARCHITECTURE.md (action_templates.json equivalent),
    kept inline here for a self-contained demo.
    """
    actions: List[str] = []

    if _has_source(evidence, "email"):
        actions += ["Quarantine suspicious email", "Block sender domain"]
    if _has_source(evidence, "endpoint"):
        actions.append("Isolate endpoint from network")
    if _has_source(evidence, "media"):
        actions.append("Flag media as unverified")
        actions.append("Revoke signing credential")
    if _has_source(evidence, "identity"):
        actions.append("Force password reset (all sessions)")

    if severity in ("high", "critical"):
        actions.append("Notify security team")
    if severity == "critical":
        actions.append("Suspend user account")
        actions.append("Freeze pending wire transfer")
        actions.append("Escalate to legal/compliance")

    # de-dupe while preserving order
    seen = set()
    unique_actions = [a for a in actions if not (a in seen or seen.add(a))]

    playbook: List[PlaybookAction] = []
    for label in unique_actions:
        risk = ACTION_RISK_TABLE.get(label, "high")  # unknown -> fail-safe high
        mode = "auto" if risk == "low" else "manual"
        playbook.append(PlaybookAction(label=label, risk_level=risk, mode=mode))
    return playbook
