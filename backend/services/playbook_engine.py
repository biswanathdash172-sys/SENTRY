"""
playbook_engine.py
-------------------
Decides recommended response actions for an alert and classifies each as
"auto" (safe, reversible) or "manual" (high-impact, needs human approval).
"""

from typing import List
from models import PlaybookAction, Evidence

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

    seen = set()
    unique_actions = [a for a in actions if not (a in seen or seen.add(a))]

    playbook: List[PlaybookAction] = []
    for label in unique_actions:
        risk = ACTION_RISK_TABLE.get(label, "high")
        mode = "auto" if risk == "low" else "manual"
        playbook.append(PlaybookAction(label=label, risk_level=risk, mode=mode))
    return playbook