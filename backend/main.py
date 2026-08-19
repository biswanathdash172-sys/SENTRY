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

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from datetime import datetime
from typing import List
import pathlib
import os

# Auto-load backend/.env so environment variables (JWT_SECRET,
# ADMIN_INVITE_CODE, etc.) don't have to be manually exported in every
# terminal session before running uvicorn. Safe no-op if .env is missing.
from dotenv import load_dotenv
load_dotenv(pathlib.Path(__file__).resolve().parent / ".env")

from models import (
    Alert, Evidence, AuditEntry, MediaVerifyRequest, MediaVerifyResult,
    ActionDecision, IngestRequest, AdminUser,
)
from services import correlation_engine, playbook_engine, media_integrity_service
from demo_data import seed_alerts
from db import database as db
from routers.admin_auth import router as admin_auth_router, get_current_admin

app = FastAPI(title="SENTRY API", version="0.3.0-demo")
app.include_router(admin_auth_router)

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
_ASSETS_DIR = _FRONTEND_DIR / "assets"
app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")

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


@app.get('/dashboard', include_in_schema=False)
def _serve_dashboard_page():
    dashboard_path = _FRONTEND_DIR / 'dashboard.html'
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    return {"detail": "Dashboard page not found"}


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


def _get_org_alert_or_404(alert_id: str, admin: AdminUser) -> Alert:
    """Like _get_alert_or_404 but also enforces org gating for mutating routes."""
    alert = _get_alert_or_404(alert_id)
    if alert.org_id is not None and alert.org_id != admin.org_id:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@app.get("/health")
def health():
    return {"status": "ok", "alerts_in_store": len(STORE)}


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------
@app.get("/alerts", response_model=List[Alert])
def list_alerts(
    source_type: str | None = None,
    status: str | None = None,
    admin: AdminUser = Depends(get_current_admin),
):
    # Gated: an admin only ever sees alerts belonging to their own org.
    # Legacy/demo-seeded alerts (org_id is None) are visible to everyone so
    # the existing demo scenarios keep working without re-seeding.
    alerts = sorted(STORE.values(), key=lambda a: a.created_at, reverse=True)
    alerts = [a for a in alerts if a.org_id is None or a.org_id == admin.org_id]
    if status:
        alerts = [a for a in alerts if a.status == status]
    if source_type and source_type != "all":
        alerts = [a for a in alerts if any(e.source_type == source_type for e in a.evidence)]
    return alerts


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, admin: AdminUser = Depends(get_current_admin)):
    alert = _get_alert_or_404(alert_id)
    if alert.org_id is not None and alert.org_id != admin.org_id:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@app.post("/alerts/{alert_id}/approve", response_model=Alert)
def approve_action(alert_id: str, action_id: str, decision: ActionDecision | None = None,
                    admin: AdminUser = Depends(get_current_admin)):
    alert = _get_org_alert_or_404(alert_id, admin)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "approved"
    who = (decision.approved_by if decision else None) or "analyst_demo_user"
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' APPROVED by {who}."))
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


@app.post("/alerts/{alert_id}/deny", response_model=Alert)
def deny_action(alert_id: str, action_id: str, decision: ActionDecision | None = None,
                 admin: AdminUser = Depends(get_current_admin)):
    alert = _get_org_alert_or_404(alert_id, admin)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "denied"
    who = (decision.approved_by if decision else None) or "analyst_demo_user"
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' DENIED by {who}."))
    db.save_alert(alert)  # best-effort persist, never blocks/raises
    return alert


@app.post("/alerts/{alert_id}/resolve", response_model=Alert)
def resolve_alert(alert_id: str, admin: AdminUser = Depends(get_current_admin)):
    alert = _get_org_alert_or_404(alert_id, admin)
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
def _ingest(source_type: str, req: IngestRequest, default_title: str,
            org_id: str | None = None) -> Alert:
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
            org_id=org_id,
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


# NOTE: org_id here is *optional auth* — these routes stay callable without
# a token so the existing demo/hackathon flows (curl, Postman, judges) keep
# working unchanged. When a bearer token IS present (as the IMAP poller
# always sends), the resulting alert is stamped with that admin's org_id
# and therefore only shows up for that org's admin.
def _optional_admin(authorization: str | None = None) -> AdminUser | None:
    if not authorization:
        return None
    try:
        return get_current_admin(authorization)
    except HTTPException:
        return None


from fastapi import Header


@app.post("/ingest/email", response_model=Alert)
def ingest_email(req: IngestRequest, authorization: str | None = Header(default=None)):
    """POST /ingest/email — e.g. a mail-gateway connector (our IMAP poller)
    pushing a suspicious-message event (lookalike domain, credential-harvest
    link). If called with a valid admin bearer token, the resulting alert
    is scoped to that admin's org."""
    admin = _optional_admin(authorization)
    return _ingest("email", req, default_title="Suspicious email signal (ingested)",
                    org_id=admin.org_id if admin else None)


@app.post("/ingest/identity", response_model=Alert)
def ingest_identity(req: IngestRequest, authorization: str | None = Header(default=None)):
    """POST /ingest/identity — e.g. an identity-provider connector pushing
    a login/auth anomaly (impossible travel, unusual MFA pattern)."""
    admin = _optional_admin(authorization)
    return _ingest("identity", req, default_title="Identity/login signal (ingested)",
                    org_id=admin.org_id if admin else None)


@app.post("/ingest/network", response_model=Alert)
def ingest_network(req: IngestRequest, authorization: str | None = Header(default=None)):
    """POST /ingest/network — e.g. a network-monitoring connector pushing
    an anomalous-traffic event."""
    admin = _optional_admin(authorization)
    return _ingest("network", req, default_title="Network signal (ingested)",
                    org_id=admin.org_id if admin else None)


@app.post("/ingest/endpoint", response_model=Alert)
def ingest_endpoint(req: IngestRequest, authorization: str | None = Header(default=None)):
    """POST /ingest/endpoint — e.g. an EDR/device-monitoring connector
    pushing a malware/process-injection event."""
    admin = _optional_admin(authorization)
    return _ingest("endpoint", req, default_title="Endpoint signal (ingested)",
                    org_id=admin.org_id if admin else None)


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