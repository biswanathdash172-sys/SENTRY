import json
import os
from pathlib import Path

# The single source of truth is now in the ai-agent module, per ARCHITECTURE.md
AI_AGENT_PLAYBOOK_DIR = Path(__file__).resolve().parent.parent.parent / "ai-agent" / "playbook"

def _load_matrix():
    try:
        with open(AI_AGENT_PLAYBOOK_DIR / "decision_matrix.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to load decision_matrix.json: {e}")
        return []

def _load_risk_table():
    try:
        with open(AI_AGENT_PLAYBOOK_DIR / "action_templates.json", "r", encoding="utf-8") as f:
            data = json.load(f)
            return {item["label"]: item["risk_level"] for item in data.get("actions", [])}
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to load action_templates.json: {e}")
        return {}

PLAYBOOK_DECISION_MATRIX = _load_matrix()
ACTION_RISK_TABLE = _load_risk_table()
