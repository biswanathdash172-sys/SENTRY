"""
playbook_engine.py
-------------------
Decides recommended response actions for an alert and classifies each as
"auto" (safe, reversible) or "manual" (high-impact, needs human approval).
"""

from typing import List
from models import PlaybookAction, Evidence, ActionDecision
from services.playbook_matrix import PLAYBOOK_DECISION_MATRIX, ACTION_RISK_TABLE

def _has_source(evidence: List[Evidence], source_type: str) -> bool:
    return any(e.source_type == source_type for e in evidence)


def generate_playbook(evidence: List[Evidence], severity: str) -> List[PlaybookAction]:
    """
    Implementation of generate_playbook using the declarative PLAYBOOK_DECISION_MATRIX
    rather than hardcoded imperative if/else branches.
    """
    actions: List[str] = []

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