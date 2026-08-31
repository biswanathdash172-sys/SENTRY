"""
risk_classifier.py
-------------------
Standalone risk classification and playbook generation for the AI agent
module, per ARCHITECTURE.md §4. Mirrors backend/services/playbook_engine.py,
split out here so it can be developed/tested without importing the
FastAPI app, and reads its action definitions from action_templates.json
(data, not hardcoded Python) so a non-engineer teammate can review/tune
the risk table during Judge Simulation prep.

FAIL-SAFE DESIGN (this is the most safety-critical file in the whole
project — see EXPLANATION.md and EXECUTION_PLAN.md Stage 10, which both
call out a misclassified "auto" action as a real security bug, not a
cosmetic one): any action label NOT found in action_templates.json
defaults to "high" risk (requires human approval) rather than being
assumed safe. An unknown action is always treated as dangerous until
proven otherwise.
"""

from dataclasses import dataclass
from typing import List, Dict, Any
import json
import os

from correlation.rules_engine import SignalEvent
from agent_config_loader import get_config

_TEMPLATES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "playbook", "action_templates.json"
)


def _load_action_templates() -> Dict[str, Dict[str, Any]]:
    """Loads action_templates.json into a {label: template} lookup dict.
    Falls back to an empty dict on any failure — combined with the
    fail-safe default below, a missing/broken templates file just means
    EVERY action requires human approval, which is the safe direction to
    fail in, never the dangerous one."""
    try:
        with open(_TEMPLATES_PATH, "r") as f:
            data = json.load(f)
        return {a["label"]: a for a in data.get("actions", [])}
    except Exception:
        return {}


_ACTION_TEMPLATES = _load_action_templates()


@dataclass
class ActionDecision:
    approved_by: str = "analyst_demo_user"
    action: str = None
    risk: str = None
    action_impact: str = None
    automation_allowed: bool = None
    approval_required: bool = None
    decision: str = None
    reason: str = None
    policy_source: str = None
    status: str = None

@dataclass
class PlaybookAction:
    label: str
    risk_level: str  # "low" | "high"
    mode: str  # "auto" | "manual"
    id: str = ""
    decision: ActionDecision = None


def classify_risk(label: str) -> str:
    """
    Looks up a single action label's risk level from action_templates.json.
    Fail-safe default: unknown label -> "high" (per
    agent_config.yaml: playbook.unknown_action_default_risk).
    """
    template = _ACTION_TEMPLATES.get(label)
    if template:
        return template["risk_level"]
    return get_config()["playbook"]["unknown_action_default_risk"]


def _has_source(events: List[SignalEvent], source_type: str) -> bool:
    return any(e.source_type == source_type for e in events)


def generate_playbook(events: List[SignalEvent], severity: str) -> List[PlaybookAction]:
    """
    Builds a recommended action list from the signal mix + severity,
    identical logic to backend/services/playbook_engine.py's
    generate_playbook(), but reading risk levels from action_templates.json
    instead of an inline Python dict.
    """
    import uuid

    labels: List[str] = []
    if _has_source(events, "email"):
        labels += ["Quarantine suspicious email", "Block sender domain"]
    if _has_source(events, "endpoint"):
        labels.append("Isolate endpoint from network")
    if _has_source(events, "media"):
        labels.append("Flag media as unverified")
        labels.append("Revoke signing credential")
    if _has_source(events, "identity"):
        labels.append("Force password reset (all sessions)")

    if severity in ("high", "critical"):
        labels.append("Notify security team")
    if severity == "critical":
        labels.append("Suspend user account")
        labels.append("Freeze pending wire transfer")
        labels.append("Escalate to legal/compliance")

    # de-dupe while preserving order
    seen = set()
    unique_labels = [l for l in labels if not (l in seen or seen.add(l))]

    playbook: List[PlaybookAction] = []
    for label in unique_labels:
        risk = classify_risk(label)
        mode = "auto" if risk == "low" else "manual"
        
        decision = ActionDecision(
            risk=risk,
            automation_allowed=(mode == 'auto'),
            approval_required=(mode == 'manual'),
            decision='AUTO_EXECUTED' if mode == 'auto' else 'MANUAL_REQUIRED',
            policy_source='ACTION_RISK_TABLE'
        )
        
        playbook.append(
            PlaybookAction(id=f"act_{uuid.uuid4().hex[:8]}", label=label, risk_level=risk, mode=mode, decision=decision)
        )
    return playbook


def generate_playbook_matrix(events: List[SignalEvent], severity: str) -> List[PlaybookAction]:
    """
    Alternate implementation of generate_playbook using the declarative PLAYBOOK_DECISION_MATRIX
    rather than hardcoded imperative if/else branches.
    """
    import uuid
    labels: List[str] = []
    
    PLAYBOOK_DECISION_MATRIX = [
        {"source": "email", "severity": None, "actions": ["Quarantine suspicious email", "Block sender domain"]},
        {"source": "endpoint", "severity": None, "actions": ["Isolate endpoint from network"]},
        {"source": "media", "severity": None, "actions": ["Flag media as unverified", "Revoke signing credential"]},
        {"source": "identity", "severity": None, "actions": ["Force password reset (all sessions)"]},
        {"source": None, "severity": ["high", "critical"], "actions": ["Notify security team"]},
        {"source": None, "severity": ["critical"], "actions": ["Suspend user account", "Freeze pending wire transfer", "Escalate to legal/compliance"]},
    ]

    for rule in PLAYBOOK_DECISION_MATRIX:
        match = False
        if rule.get("source"):
            if _has_source(events, rule["source"]):
                match = True
        elif rule.get("severity"):
            if severity in rule["severity"]:
                match = True
                
        if match:
            labels.extend(rule["actions"])

    # de-dupe while preserving order
    seen = set()
    unique_labels = [l for l in labels if not (l in seen or seen.add(l))]

    playbook: List[PlaybookAction] = []
    for label in unique_labels:
        risk = classify_risk(label)
        mode = "auto" if risk == "low" else "manual"
        
        decision = ActionDecision(
            risk=risk,
            automation_allowed=(mode == 'auto'),
            approval_required=(mode == 'manual'),
            decision='AUTO_EXECUTED' if mode == 'auto' else 'MANUAL_REQUIRED',
            policy_source='PLAYBOOK_DECISION_MATRIX'
        )
        
        playbook.append(
            PlaybookAction(id=f"act_{uuid.uuid4().hex[:8]}", label=label, risk_level=risk, mode=mode, decision=decision)
        )
    return playbook