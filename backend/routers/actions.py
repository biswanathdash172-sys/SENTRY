"""
routers/actions.py
-------------------
Playbook-action decisions (approve/deny) and the connector-style
/ingest/* routes. Moved out of main.py verbatim — no logic changed, only
relocated behind an APIRouter.

These two groups live together because both are "things that mutate an
alert's state based on an external input" (a human decision, or a new
piece of evidence arriving) — as opposed to routers/alerts.py, which is
read/lifecycle, and routers/media_verify.py, which is a stateless check.
"""

from fastapi import APIRouter, HTTPException

from models import (
    Alert, Evidence, AuditEntry, ActionDecision, IngestRequest,
)
from services import correlation_engine, playbook_engine
from db import database as db
from store import STORE, get_alert_or_404

router = APIRouter(tags=["actions"])


@router.post("/alerts/{alert_id}/approve", response_model=Alert)
def approve_action(alert_id: str, action_id: str, decision: ActionDecision | None = None):
    alert = get_alert_or_404(alert_id)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "approved"
    who = (decision.approved_by if decision else None) or "analyst_demo_user"
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' APPROVED by {who}."))
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


@router.post("/alerts/{alert_id}/deny", response_model=Alert)
def deny_action(alert_id: str, action_id: str, decision: ActionDecision | None = None):
    alert = get_alert_or_404(alert_id)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "denied"
    who = (decision.approved_by if decision else None) or "analyst_demo_user"
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' DENIED by {who}."))
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


# ---------------------------------------------------------------------------
# Ingestion routes (connector-style stubs)
# ---------------------------------------------------------------------------
# These prove "many real systems can feed in" without needing a live Gmail/
# Okta/EDR/network-tap integration this hackathon. Each route:
#   1. Builds a normal Evidence object for its source_type.
#   2. Calls the SAME correlation_engine.correlate() used by /alerts/simulate
#      and demo_data.py — no separate/parallel logic.
#   3. Runs the result through the SAME playbook_engine.generate_playbook().
#   4. Stores a new Alert and returns it.
#
# Fail-safe by design: a bad request (empty description, out-of-range
# confidence, wrong type) is rejected by Pydantic validation and returns a
# clean 400/422 — it can never reach correlation_engine with malformed data,
# and it can never crash the app with a 500.
def _ingest(source_type: str, req: IngestRequest, default_title: str) -> Alert:
    try:
        evidence = [
            Evidence(
                source_type=source_type,  # type: ignore[arg-type]
                description=req.description,
                confidence=req.confidence,
            )
        ]
        title_hint = req.title_hint or default_title
        correlated = correlation_engine.correlate(evidence, title_hint=title_hint)
        alert = Alert(
            title=correlated["title"],
            severity=correlated["severity"],
            evidence=correlated["evidence"],
            attack_chain=correlated["attack_chain"],
            playbook=playbook_engine.generate_playbook(evidence, correlated["severity"]),
            audit_log=[
                AuditEntry(
                    message=f"Alert created via /ingest/{source_type} "
                    f"from 1 real-time evidence source."
                )
            ],
        )
        STORE[alert.id] = alert
        db.save_alert(alert)  # best-effort persist, never blocks/raises
        return alert
    except HTTPException:
        raise
    except Exception as exc:
        # Fail-safe: never let an ingestion route 500 the whole demo.
        raise HTTPException(status_code=400, detail=f"Could not ingest {source_type} evidence: {exc}")


@router.post("/ingest/email", response_model=Alert)
def ingest_email(req: IngestRequest):
    """POST /ingest/email — e.g. a mail-gateway connector pushing a
    suspicious-message event (lookalike domain, credential-harvest link)."""
    return _ingest("email", req, default_title="Suspicious email signal (ingested)")


@router.post("/ingest/identity", response_model=Alert)
def ingest_identity(req: IngestRequest):
    """POST /ingest/identity — e.g. an identity-provider connector pushing
    a login/auth anomaly (impossible travel, unusual MFA pattern)."""
    return _ingest("identity", req, default_title="Identity/login signal (ingested)")


@router.post("/ingest/network", response_model=Alert)
def ingest_network(req: IngestRequest):
    """POST /ingest/network — e.g. a network-monitoring connector pushing
    an anomalous-traffic event."""
    return _ingest("network", req, default_title="Network signal (ingested)")


@router.post("/ingest/endpoint", response_model=Alert)
def ingest_endpoint(req: IngestRequest):
    """POST /ingest/endpoint — e.g. an EDR/device-monitoring connector
    pushing a malware/process-injection event."""
    return _ingest("endpoint", req, default_title="Endpoint signal (ingested)")