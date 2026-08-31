import pytest
from playbook import risk_classifier

def test_classify_risk_fail_closed(monkeypatch):
    # Temporarily empty the action templates dict
    monkeypatch.setattr(risk_classifier, "_ACTION_TEMPLATES", {})
    
    # Any unknown action must resolve to the config-driven unknown_action_default_risk, which is 'high'
    assert risk_classifier.classify_risk("Some Future Unknown Action") == "high"
