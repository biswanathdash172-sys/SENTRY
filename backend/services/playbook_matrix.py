PLAYBOOK_DECISION_MATRIX = [
    {"source": "email", "severity": None, "actions": ["Quarantine suspicious email", "Block sender domain"]},
    {"source": "endpoint", "severity": None, "actions": ["Isolate endpoint from network"]},
    {"source": "media", "severity": None, "actions": ["Flag media as unverified", "Revoke signing credential"]},
    {"source": "identity", "severity": None, "actions": ["Force password reset (all sessions)"]},
    {"source": None, "severity": ["high", "critical"], "actions": ["Notify security team"]},
    {"source": None, "severity": ["critical"], "actions": ["Suspend user account", "Freeze pending wire transfer", "Escalate to legal/compliance"]},
]
