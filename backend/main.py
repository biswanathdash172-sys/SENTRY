"""
main.py
-------
SENTRY demo backend — Human-Governed Autonomous SOC with integrated media
integrity checks. Built per ARCHITECTURE.md, scoped down for a hackathon
demo per the user's request:

  * In-memory store instead of Postgres (see models.py docstring for the
    drop-in upgrade path). This is a deliberate "Demo Mode" choice: no DB
    connection to fail during judging.
  * Polling-friendly REST endpoints instead of a WebSocket (simpler,
    equally "live-feeling" at demo scale, nothing to reconnect if wifi
    hiccups on stage).
  * Every mutating endpoint is wrapped so a bad request returns a clean
    4xx instead of a 500 — the app must never crash mid-demo.

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000

Then open ../frontend/index.html directly in a browser (it talks to
http://localhost:8000 by default).
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import List

from models import (
    Alert, Evidence, AuditEntry, MediaVerifyRequest, MediaVerifyResult, ActionDecision,
)
from services import correlation_engine, playbook_engine, media_integrity_service
from demo_data import seed_alerts

app = FastAPI(title="SENTRY API", version="0.1.0-demo")

# Wide-open CORS: this is a hackathon demo served from a local static HTML
# file (file:// or a simple http server), not a production deployment.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# In-memory "database". Seeded on boot so the dashboard is never empty.
# ---------------------------------------------------------------------------
STORE: dict[str, Alert] = seed_alerts()


def _get_alert_or_404(alert_id: str) -> Alert:
    alert = STORE.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@app.get("/health")
def health():
    return {"status": "ok", "alerts_in_store": len(STORE)}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@app.get("/alerts", response_model=List[Alert])
def list_alerts(source_type: str | None = None, status: str | None = None):
    """GET /alerts — supports the frontend's filter chips (All / Identity /
    Network / Media / Endpoint / Email) and open/resolved filtering."""
    alerts = sorted(STORE.values(), key=lambda a: a.created_at, reverse=True)
    if status:
        alerts = [a for a in alerts if a.status == status]
    if source_type and source_type != "all":
        alerts = [a for a in alerts if any(e.source_type == source_type for e in a.evidence)]
    return alerts


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str):
    return _get_alert_or_404(alert_id)


@app.post("/alerts/{alert_id}/approve", response_model=Alert)
def approve_action(alert_id: str, action_id: str, decision: ActionDecision | None = None):
    alert = _get_alert_or_404(alert_id)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "approved"
    who = (decision.approved_by if decision else None) or "analyst_demo_user"
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' APPROVED by {who}."))
    return alert


@app.post("/alerts/{alert_id}/deny", response_model=Alert)
def deny_action(alert_id: str, action_id: str, decision: ActionDecision | None = None):
    alert = _get_alert_or_404(alert_id)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "denied"
    who = (decision.approved_by if decision else None) or "analyst_demo_user"
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' DENIED by {who}."))
    return alert


@app.post("/alerts/{alert_id}/resolve", response_model=Alert)
def resolve_alert(alert_id: str):
    alert = _get_alert_or_404(alert_id)
    alert.status = "resolved"
    alert.audit_log.append(AuditEntry(message="Alert manually marked resolved by analyst."))
    return alert


# ---------------------------------------------------------------------------
# Media verification (S26 module, plugged in as an evidence source)
# ---------------------------------------------------------------------------
@app.post("/media/verify", response_model=MediaVerifyResult)
def verify_media(req: MediaVerifyRequest):
    return media_integrity_service.verify_media(req)


# ---------------------------------------------------------------------------
# Simulate incoming alert — mirrors the prototype's "Simulate incoming
# alert" button (EXPLANATION.md §5) and the flagship demo flow
# (ARCHITECTURE.md §7): media evidence -> correlation -> playbook.
# ---------------------------------------------------------------------------
@app.post("/alerts/simulate", response_model=Alert)
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
    return alert
