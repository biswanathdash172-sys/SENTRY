"""
main.py
-------
SENTRY demo backend — Human-Governed Autonomous SOC with integrated media
integrity checks.

REFACTOR NOTE (org auth): the old local JSON-store admin auth
(routers/admin_auth.py + services/auth_service.py + db/org_store.py) has
been removed entirely. Organization + employee identity is now backed by
Supabase (see services/supabase_service.py, routers/org_auth.py). The old
"accept any credentials" demo `/login` stub that used to live directly on
`app` has also been removed — /login is now real, served by org_auth.py.

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
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
# SUPABASE_URL, SUPABASE_KEY, etc.) don't have to be manually exported in
# every terminal session before running uvicorn. Safe no-op if .env is missing.
from dotenv import load_dotenv
load_dotenv(pathlib.Path(__file__).resolve().parent / ".env")

from models import (
    Alert, Evidence, AuditEntry, MediaVerifyRequest, MediaVerifyResult,
    ActionDecision, IngestRequest, AdminUser,
)
from services import correlation_engine, playbook_engine, media_integrity_service
from demo_data import seed_alerts
from db import database as db
from routers.org_auth import router as org_auth_router, get_current_admin

app = FastAPI(title="SENTRY API", version="0.4.0-demo")
app.include_router(org_auth_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve the static frontend from the project's frontend/ directory.
_PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent
_FRONTEND_DIR = _PROJECT_ROOT / "frontend"
app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")
_ASSETS_DIR = _FRONTEND_DIR / "assets"
app.mount("/assets", StaticFiles(directory=str(_ASSETS_DIR)), name="assets")


@app.get("/", include_in_schema=False)
def _serve_frontend_index():
    index_path = _FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return {"detail": "Frontend index.html not found; API is available under /docs"}


@app.get("/get-access", include_in_schema=False)
def _serve_get_access_page():
    """New step in the login flow: validates an org ID + org preset
    password against Supabase before the employee login page is used."""
    page_path = _FRONTEND_DIR / "get-access.html"
    if page_path.exists():
        return FileResponse(str(page_path))
    return {"detail": "Get Access page not found"}


@app.get("/login", include_in_schema=False)
def _serve_login_page():
    login_path = _FRONTEND_DIR / "login.html"
    if login_path.exists():
        return FileResponse(str(login_path))
    return {"detail": "Login page not found"}


@app.get("/dashboard", include_in_schema=False)
def _serve_dashboard_page():
    dashboard_path = _FRONTEND_DIR / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path))
    return {"detail": "Dashboard page not found"}


# NOTE: the old `POST /login` demo stub ("accept any credentials, return
# f'demo-token-{username}'") has been removed. Real employee login is now
# `POST /login` as registered by routers/org_auth.py (employee_id +
# password, checked against Supabase, returns a signed JWT).


# ---------------------------------------------------------------------------
# Storage bootstrap (unchanged from before this refactor) — Postgres if
# DATABASE_URL is reachable, else in-memory STORE. Never fails to boot.
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
    if alert.org_id is not None and str(alert.org_id) != str(admin.org_id):
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
    alerts = sorted(STORE.values(), key=lambda a: a.created_at, reverse=True)
    alerts = [a for a in alerts if a.org_id is None or str(a.org_id) == str(admin.org_id)]
    if status:
        alerts = [a for a in alerts if a.status == status]
    if source_type and source_type != "all":
        alerts = [a for a in alerts if any(e.source_type == source_type for e in a.evidence)]
    return alerts


@app.get("/alerts/{alert_id}", response_model=Alert)
def get_alert(alert_id: str, admin: AdminUser = Depends(get_current_admin)):
    alert = _get_alert_or_404(alert_id)
    if alert.org_id is not None and str(alert.org_id) != str(admin.org_id):
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
    who = (decision.approved_by if decision else None) or admin.employee_id
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' APPROVED by {who}."))
    db.save_alert(alert)
    return alert


@app.post("/alerts/{alert_id}/deny", response_model=Alert)
def deny_action(alert_id: str, action_id: str, decision: ActionDecision | None = None,
                 admin: AdminUser = Depends(get_current_admin)):
    alert = _get_org_alert_or_404(alert_id, admin)
    action = next((a for a in alert.playbook if a.id == action_id), None)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found on alert")
    action.mode = "denied"
    who = (decision.approved_by if decision else None) or admin.employee_id
    alert.audit_log.append(AuditEntry(message=f"Action '{action.label}' DENIED by {who}."))
    db.save_alert(alert)
    return alert


@app.post("/alerts/{alert_id}/resolve", response_model=Alert)
def resolve_alert(alert_id: str, admin: AdminUser = Depends(get_current_admin)):
    alert = _get_org_alert_or_404(alert_id, admin)
    alert.status = "resolved"
    alert.audit_log.append(AuditEntry(message="Alert manually marked resolved by analyst."))
    db.save_alert(alert)
    return alert


# ---------------------------------------------------------------------------
# Media verification (S26 module, plugged in as an evidence source)
# ---------------------------------------------------------------------------
@app.post("/media/verify", response_model=MediaVerifyResult)
def verify_media(req: MediaVerifyRequest):
    return media_integrity_service.verify_media(req)


# ---------------------------------------------------------------------------
# Ingestion routes (connector-style stubs) — unchanged logic, only the
# optional-admin resolution now goes through the new Supabase-backed
# get_current_admin instead of the old local-store version.
# ---------------------------------------------------------------------------
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
        db.save_alert(alert)
        return alert
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not ingest {source_type} evidence: {exc}")


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
    admin = _optional_admin(authorization)
    return _ingest("email", req, default_title="Suspicious email signal (ingested)",
                    org_id=admin.org_id if admin else None)


@app.post("/ingest/identity", response_model=Alert)
def ingest_identity(req: IngestRequest, authorization: str | None = Header(default=None)):
    admin = _optional_admin(authorization)
    return _ingest("identity", req, default_title="Identity/login signal (ingested)",
                    org_id=admin.org_id if admin else None)


@app.post("/ingest/network", response_model=Alert)
def ingest_network(req: IngestRequest, authorization: str | None = Header(default=None)):
    admin = _optional_admin(authorization)
    return _ingest("network", req, default_title="Network signal (ingested)",
                    org_id=admin.org_id if admin else None)


@app.post("/ingest/endpoint", response_model=Alert)
def ingest_endpoint(req: IngestRequest, authorization: str | None = Header(default=None)):
    admin = _optional_admin(authorization)
    return _ingest("endpoint", req, default_title="Endpoint signal (ingested)",
                    org_id=admin.org_id if admin else None)


# ---------------------------------------------------------------------------
# Simulate incoming alert
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
    db.save_alert(alert)
    return alert
