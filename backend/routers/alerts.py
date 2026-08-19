"""
routers/alerts.py
------------------
Alert read/lifecycle routes: list, get-by-id, resolve, and the demo
"simulate incoming alert" endpoint. Moved out of main.py verbatim — no
logic changed, only relocated behind an APIRouter.
"""

from typing import List

from fastapi import APIRouter

from models import (
    Alert, Evidence, AuditEntry, MediaVerifyRequest,
)
from services import correlation_engine, playbook_engine, media_integrity_service
from db import database as db
from Store import STORE, get_alert_or_404

router = APIRouter(tags=["alerts"])


@router.get("/alerts", response_model=List[Alert])
def list_alerts(source_type: str | None = None, status: str | None = None):
    alerts = sorted(STORE.values(), key=lambda a: a.created_at, reverse=True)
    if status:
        alerts = [a for a in alerts if a.status == status]
    if source_type and source_type != "all":
        alerts = [a for a in alerts if any(e.source_type == source_type for e in a.evidence)]
    return alerts


@router.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str):
    return get_alert_or_404(alert_id)


@router.post("/alerts/{alert_id}/resolve", response_model=Alert)
def resolve_alert(alert_id: str):
    alert = get_alert_or_404(alert_id)
    alert.status = "resolved"
    alert.audit_log.append(AuditEntry(message="Alert manually marked resolved by analyst."))
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


# ---------------------------------------------------------------------------
# Simulate incoming alert — mirrors the prototype's "Simulate incoming
# alert" button: media evidence -> correlation -> playbook.
# ---------------------------------------------------------------------------
@router.post("/alerts/simulate", response_model=Alert)
def simulate_alert(scenario: str = "deepfake_wire_fraud"):
    if scenario == "deepfake_wire_fraud":
        media_result = media_integrity_service.verify_media(
            MediaVerifyRequest(filename="urgent_cfo_deepfake_request.mp4", force_verdict="deepfake")
        )
        evidence = [
            media_integrity_service.result_to_evidence(media_result),
            Evidence(
                source_type="email",
                description="Follow-up email from lookalike domain requesting urgent wire transfer.",
                confidence=0.68,
            ),
            Evidence(
                source_type="identity",
                description="Request targets finance staff, bypassing normal approval chain.",
                confidence=0.5,
            ),
        ]
        title_hint = "Likely deepfake-powered wire-fraud attempt (simulated)"
    elif scenario == "phishing":
        evidence = [
            Evidence(source_type="email", description="Email with credential-harvesting link sent to 12 staff.", confidence=0.6),
            Evidence(source_type="identity", description="Login attempt from unusual geolocation shortly after.", confidence=0.55),
        ]
        title_hint = "Likely credential-phishing follow-through (simulated)"
    else:
        evidence = [Evidence(source_type="network", description="Anomalous traffic pattern detected.", confidence=0.4)]
        title_hint = "Unclassified anomaly (simulated)"

    correlated = correlation_engine.correlate(evidence, title_hint=title_hint)
    alert = Alert(
        title=correlated["title"],
        severity=correlated["severity"],
        evidence=correlated["evidence"],
        attack_chain=correlated["attack_chain"],
        playbook=playbook_engine.generate_playbook(evidence, correlated["severity"]),
        audit_log=[AuditEntry(message=f"Simulated alert created from {len(evidence)} evidence source(s).")],
    )
    STORE[alert.id] = alert
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert
