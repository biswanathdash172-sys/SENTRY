import pytest
from services.risk_classifier import classify_cvss, RiskTier
from services import playbook_engine
from models import Evidence

class TestFailClosedRiskClassifier:
    def test_classify_cvss_fail_closed(self):
        # Missing score
        res = classify_cvss(None)
        assert res.tier == RiskTier.HIGH_RISKY
        
        # Unparseable score
        res = classify_cvss('not-a-number')
        assert res.tier == RiskTier.HIGH_RISKY
        
        # Out of bounds scores
        res = classify_cvss(11.0)
        assert res.tier == RiskTier.HIGH_RISKY
        
        res = classify_cvss(-1.0)
        assert res.tier == RiskTier.HIGH_RISKY

class TestFailClosedPlaybookEngine:
    def test_generate_playbook_empty_templates(self, monkeypatch):
        # Temporarily empty the action risk table
        monkeypatch.setattr(playbook_engine, "ACTION_RISK_TABLE", {})
        
        evidence = [Evidence(source_type="email", description="test", confidence=0.9)]
        
        playbook = playbook_engine.generate_playbook(evidence, severity="critical")
        
        # generate_playbook creates actions based on rules, all unknown ones should default to high/manual
        assert len(playbook) > 0
        for action in playbook:
            assert action.risk_level == 'high'
            assert action.mode == 'manual'
