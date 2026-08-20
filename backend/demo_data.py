"""
demo_data.py
------------
Seeds the in-memory store with a few alerts, including the flagship
"deepfake CFO wire-fraud" scenario, already fully correlated.
"""

from datetime import datetime, timedelta
from models import Alert, Evidence, AuditEntry
from services.correlation_engine import build_attack_chain, combined_confidence, severity_from_confidence
from services.playbook_engine import generate_playbook


def _flagship_deepfake_alert() -> Alert:
    now = datetime.utcnow()
    evidence = [
        Evidence(
            source_type="media",
            description="Video claiming to be the CFO failed signature check and scored 91% deepfake-likelihood.",
            confidence=0.91,
            timestamp=now - timedelta(minutes=6),
        ),
        Evidence(
            source_type="email",
            description="Accompanying email sent from lookalike domain 'cfo-office-corp.com' (real domain: corp.com).",
            confidence=0.72,
            timestamp=now - timedelta(minutes=5),
        ),
        Evidence(
            source_type="identity",
            description="Message sent to 3 finance staff simultaneously, outside normal CFO communication pattern.",
            confidence=0.58,
            timestamp=now - timedelta(minutes=4),
        ),
    ]
    confidence = combined_confidence(evidence)
    severity = severity_from_confidence(confidence)
    alert = Alert(
        org_id=None,
        title="Likely deepfake-powered wire-fraud attempt (CFO impersonation)",
        severity=severity,
        evidence=evidence,
        attack_chain=build_attack_chain(evidence),
        playbook=generate_playbook(evidence, severity),
        audit_log=[
            AuditEntry(message="Alert created by correlation_engine from 3 evidence sources."),
            AuditEntry(message="Low-risk actions (quarantine email, block domain, revoke credential) auto-executed."),
        ],
    )
    return alert


def _network_alert() -> Alert:
    now = datetime.utcnow()
    evidence = [
        Evidence(
            source_type="network",
            description="Unusual outbound traffic spike from finance subnet to unrecognized external IP.",
            confidence=0.55,
            timestamp=now - timedelta(minutes=40),
        ),
        Evidence(
            source_type="endpoint",
            description="Endpoint FIN-LAPTOP-12 flagged for process injection attempt.",
            confidence=0.62,
            timestamp=now - timedelta(minutes=38),
        ),
    ]
    confidence = combined_confidence(evidence)
    severity = severity_from_confidence(confidence)
    return Alert(
        org_id=None,
        title="Possible lateral movement on finance subnet",
        severity=severity,
        evidence=evidence,
        attack_chain=build_attack_chain(evidence),
        playbook=generate_playbook(evidence, severity),
        audit_log=[AuditEntry(message="Alert created by correlation_engine from 2 evidence sources.")],
    )


def _resolved_alert() -> Alert:
    now = datetime.utcnow()
    evidence = [
        Evidence(
            source_type="identity",
            description="Login from new device, but confirmed by user via MFA within 60s.",
            confidence=0.15,
            timestamp=now - timedelta(hours=3),
        ),
    ]
    severity = "low"
    return Alert(
        org_id=None,
        title="New-device login (confirmed by user)",
        severity=severity,
        status="resolved",
        evidence=evidence,
        attack_chain=build_attack_chain(evidence),
        playbook=generate_playbook(evidence, severity),
        audit_log=[
            AuditEntry(message="Alert created by correlation_engine from 1 evidence source."),
            AuditEntry(message="Auto-resolved: MFA confirmation matched login within policy window."),
        ],
    )


def seed_alerts() -> dict:
    alerts = [_flagship_deepfake_alert(), _network_alert(), _resolved_alert()]
    return {a.id: a for a in alerts}
