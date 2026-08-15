"""
main.py
-------
SENTRY demo backend — Human-Governed Autonomous SOC with integrated media
integrity checks.

  * In-memory store instead of Postgres (see models.py docstring for the
    drop-in upgrade path).
  * Polling-friendly REST endpoints instead of a WebSocket.
  * Every mutating endpoint is wrapped so a bad request returns a clean
    4xx instead of a 500 — the app must never crash mid-demo.

NEW IN THIS VERSION (Biswanath, Priority 0 — see BISWANATH_TASKS.txt):
  * POST /ingest/email, /ingest/identity, /ingest/network, /ingest/endpoint
    Thin "connector-style" routes so the "many systems feed in" story is
    demonstrable, not just described. Each one just builds a normal
    Evidence object and hands it to the SAME correlation_engine.correlate()
    used everywhere else — no separate ingestion path, no shortcut.

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000

Then open ../frontend/index.html directly in a browser (it talks to
http://localhost:8000 by default).
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from datetime import datetime
from typing import List
import pathlib
import os

from models import (
    Alert, Evidence, AuditEntry, MediaVerifyRequest, MediaVerifyResult,
    ActionDecision, IngestRequest,
)
from services import correlation_engine, playbook_engine, media_integrity_service
from demo_data import seed_alerts
from db import database as db

app = FastAPI(title="SENTRY API", version="0.3.0-demo")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static frontend from the project's frontend/ directory. Mounts are always registered; when files are missing a helpful JSON is returned.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"
# Mount frontend directory at /static so assets can be fetched from /static/...
app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")

@app.get("/", include_in_schema=False)
def _serve_frontend_index():
    index_path = _FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"detail": "Frontend index.html not found; API is available under /docs"}


@app.get('/login', include_in_schema=False)
def _serve_login_page():
    login_path = _FRONTEND_DIR / 'login.html'
    if login_path.exists():
        return FileResponse(str(login_path))
    return {"detail": "Login page not found"}


from fastapi import Form

@app.post('/login')
def _login(username: str = Form(...), password: str = Form(...)):
    # Demo-only: accept any credentials and return a demo token
    token = f"demo-token-{username}"
    return {"status": "ok", "user": username, "token": token}


# ---------------------------------------------------------------------------
# Storage bootstrap (Biswanath, Priority 2 - Postgres swap-in). Strict
# drop-in: db.init_db() NEVER raises, so the app boots identically whether
# or not a real Postgres DATABASE_URL is configured or reachable.
#
#   - DB reachable AND has existing alerts  -> load them (state survives a
#     restart, proving the system is real, per ROADMAP.md Day 4).
#   - DB reachable but empty (first boot)    -> seed demo data, persist it
#     immediately so it's there on the next restart too.
#   - DB unreachable / DEMO_MODE=true        -> exactly the old behavior:
#     pure in-memory STORE, seeded fresh every boot. Never fails.
#
# STORE (the in-memory dict) remains the single source of truth for every
# request in this process. The DB is a best-effort mirror written on every
# mutation, never a blocking dependency of any route.
# ---------------------------------------------------------------------------
db.init_db()

if db.db_available():
    STORE: dict[str, Alert] = db.load_all_alerts()
    if not STORE:
        STORE = seed_alerts()
        for seeded_alert in STORE.values():
            db.save_alert(seeded_alert)
else:
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
    db.save_alert(alert)  # best-effort persist, never blocks/raises
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
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


@app.post("/alerts/{alert_id}/resolve", response_model=Alert)
def resolve_alert(alert_id: str):
    alert = _get_alert_or_404(alert_id)
    alert.status = "resolved"
    alert.audit_log.append(AuditEntry(message="Alert manually marked resolved by analyst."))
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


# ---------------------------------------------------------------------------
# Media verification (S26 module, plugged in as an evidence source)
# ---------------------------------------------------------------------------
@app.post("/media/verify", response_model=MediaVerifyResult)
def verify_media(req: MediaVerifyRequest):
    return media_integrity_service.verify_media(req)


# ---------------------------------------------------------------------------
# NEW — Ingestion routes (connector-style stubs)
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


@app.post("/ingest/email", response_model=Alert)
def ingest_email(req: IngestRequest):
    """POST /ingest/email — e.g. a mail-gateway connector pushing a
    suspicious-message event (lookalike domain, credential-harvest link)."""
    return _ingest("email", req, default_title="Suspicious email signal (ingested)")


@app.post("/ingest/identity", response_model=Alert)
def ingest_identity(req: IngestRequest):
    """POST /ingest/identity — e.g. an identity-provider connector pushing
    a login/auth anomaly (impossible travel, unusual MFA pattern)."""
    return _ingest("identity", req, default_title="Identity/login signal (ingested)")


@app.post("/ingest/network", response_model=Alert)
def ingest_network(req: IngestRequest):
    """POST /ingest/network — e.g. a network-monitoring connector pushing
    an anomalous-traffic event."""
    return _ingest("network", req, default_title="Network signal (ingested)")


@app.post("/ingest/endpoint", response_model=Alert)
def ingest_endpoint(req: IngestRequest):
    """POST /ingest/endpoint — e.g. an EDR/device-monitoring connector
    pushing a malware/process-injection event."""
    return _ingest("endpoint", req, default_title="Endpoint signal (ingested)")


# ---------------------------------------------------------------------------
# Simulate incoming alert — mirrors the prototype's "Simulate incoming
# alert" button: media evidence -> correlation -> playbook.
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
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert