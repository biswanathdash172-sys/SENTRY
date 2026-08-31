"""
playbook_engine.py
-------------------
Decides recommended response actions for an alert and classifies each as
"auto" (safe, reversible) or "manual" (high-impact, needs human approval).
"""

from typing import List
from models import PlaybookAction, Evidence, ActionDecision

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
        
        decision = ActionDecision(
            risk=risk,
            automation_allowed=(mode == 'auto'),
            approval_required=(mode == 'manual'),
            decision='AUTO_EXECUTED' if mode == 'auto' else 'MANUAL_REQUIRED',
            policy_source='ACTION_RISK_TABLE'
        )
        playbook.append(PlaybookAction(label=label, risk_level=risk, mode=mode, decision=decision))
    return playbook


def generate_playbook_matrix(evidence: List[Evidence], severity: str) -> List[PlaybookAction]:
    """
    Alternate implementation of generate_playbook using the declarative PLAYBOOK_DECISION_MATRIX
    rather than hardcoded imperative if/else branches.
    """
    actions: List[str] = []

    from services.playbook_matrix import PLAYBOOK_DECISION_MATRIX

    for rule in PLAYBOOK_DECISION_MATRIX:
        match = False
        if rule.get("source"):
            if _has_source(evidence, rule["source"]):
                match = True
        elif rule.get("severity"):
            if severity in rule["severity"]:
                match = True
                
        if match:
            actions.extend(rule["actions"])

    seen = set()
    unique_actions = [a for a in actions if not (a in seen or seen.add(a))]

    playbook: List[PlaybookAction] = []
    for label in unique_actions:
        risk = ACTION_RISK_TABLE.get(label, "high")
        mode = "auto" if risk == "low" else "manual"
        
        decision = ActionDecision(
            risk=risk,
            automation_allowed=(mode == 'auto'),
            approval_required=(mode == 'manual'),
            decision='AUTO_EXECUTED' if mode == 'auto' else 'MANUAL_REQUIRED',
            policy_source='PLAYBOOK_DECISION_MATRIX'
        )
        playbook.append(PlaybookAction(label=label, risk_level=risk, mode=mode, decision=decision))
    return playbook