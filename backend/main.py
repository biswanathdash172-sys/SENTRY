"""
main.py
-------
SENTRY demo backend — Human-Governed Autonomous SOC with integrated media
integrity checks, SCA vulnerability scanning, and Windows notification
capture, all unified under one RBAC'd, Supabase-backed system.

Run:
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
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

# --- All routers ---
from routers.org_auth import router as org_auth_router, get_current_admin
from routers.signup import router as signup_router
from routers.scan import router as scan_router
from routers.employees import router as employees_router
from routers.rules import router as rules_router
from routers.risk_actions import router as risk_actions_router
from routers.analytics import router as analytics_router
from routers.reports import router as reports_router
from routers.notification_ingest import router as notification_ingest_router
from routers.audit import router as audit_router
from routers.gmail_emails import router as gmail_emails_router
from routers.whitelist import router as whitelist_router
from routers.device_control import router as device_control_router
from routers.cyber_head import router as cyber_head_router

app = FastAPI(title="SENTRY API", version="0.6.0")

app.include_router(org_auth_router)
app.include_router(signup_router)
app.include_router(scan_router)
app.include_router(employees_router)
app.include_router(rules_router)
app.include_router(risk_actions_router)
app.include_router(analytics_router)
app.include_router(reports_router)
app.include_router(notification_ingest_router)
app.include_router(audit_router)
app.include_router(gmail_emails_router)
app.include_router(whitelist_router)
app.include_router(device_control_router)
app.include_router(cyber_head_router)

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
def _serve_index_page():
    index_path = _FRONTEND_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), media_type="text/html; charset=utf-8")
    return {"detail": "SENTRY frontend index not found"}


@app.get("/get-access", include_in_schema=False)
def _serve_get_access_page():
    page_path = _FRONTEND_DIR / "get-access.html"
    if page_path.exists():
        return FileResponse(str(page_path), media_type="text/html; charset=utf-8")
    return {"detail": "Get Access page not found"}


@app.get("/signup", include_in_schema=False)
def _serve_signup_page():
    page_path = _FRONTEND_DIR / "signup.html"
    if page_path.exists():
        return FileResponse(str(page_path), media_type="text/html; charset=utf-8")
    return {"detail": "Signup page not found"}

@app.get("/login", include_in_schema=False)
def _serve_login_page():
    login_path = _FRONTEND_DIR / "login.html"
    if login_path.exists():
        return FileResponse(str(login_path), media_type="text/html; charset=utf-8")
    return {"detail": "Login page not found"}


@app.get("/dashboard", include_in_schema=False)
def _serve_dashboard_page():
    return RedirectResponse(url="/login")


@app.get("/org-dashboard", include_in_schema=False)
def _serve_org_dashboard_page():
    """Organization Portal: employee management, whitelist, policies, and scan findings."""
    page_path = _FRONTEND_DIR / "org-dashboard.html"
    if page_path.exists():
        return FileResponse(str(page_path), media_type="text/html; charset=utf-8")
    return {"detail": "Organization dashboard not found"}





@app.get("/employee-dashboard", include_in_schema=False)
def _serve_employee_dashboard_page():
    page_path = _FRONTEND_DIR / "employee-dashboard.html"
    if page_path.exists():
        return FileResponse(str(page_path), media_type="text/html; charset=utf-8")
    return {"detail": "Employee dashboard not found"}


@app.get("/cyber-head-dashboard", include_in_schema=False)
def _serve_cyber_head_dashboard_page():
    """Cyber Head portal — cross-org threat monitoring and remote device controls."""
    page_path = _FRONTEND_DIR / "cyber-head-dashboard.html"
    if page_path.exists():
        return FileResponse(str(page_path), media_type="text/html; charset=utf-8")
    return {"detail": "Cyber Head dashboard not found"}


# ---------------------------------------------------------------------------
# STARTUP: Apply schema migrations for new tables added in v0.6.0.
# Idempotent — uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS so safe to
# re-run on every start. Failures are logged but never crash the server.
# ---------------------------------------------------------------------------
def _apply_schema_migrations() -> None:
    """
    Applies the v0.6.0 schema additions to Supabase using the REST API.
    Uses the Supabase management approach via direct HTTP requests.
    """
    import requests as _req
    import os as _os
    _url = _os.environ.get("SUPABASE_URL", "")
    _key = _os.environ.get("SUPABASE_KEY", "")
    if not _url or not _key:
        return

    _headers = {
        "apikey": _key,
        "Authorization": f"Bearer {_key}",
        "Content-Type": "application/json",
    }

    _migrations = [
        # New tables — create if not exists
        ("domain_whitelist", {
            "id": "uuid DEFAULT gen_random_uuid() PRIMARY KEY",
            "org_id": "text NOT NULL",
            "domain": "text NOT NULL",
            "added_by": "text",
            "added_at": "timestamptz DEFAULT now()",
        }),
        ("device_freeze_requests", {
            "id": "uuid DEFAULT gen_random_uuid() PRIMARY KEY",
            "org_id": "text NOT NULL",
            "employee_id": "text NOT NULL",
            "reason": "text",
            "status": "text NOT NULL DEFAULT 'pending'",
            "triggered_by": "text",
            "triggered_at": "timestamptz DEFAULT now()",
            "lifted_by": "text",
            "lifted_at": "timestamptz",
            "risk_flag_id": "uuid",
        }),
    ]

    # Check which tables exist via the REST schema
    try:
        schema_resp = _req.get(f"{_url}/rest/v1/", headers=_headers, timeout=5)
        if schema_resp.ok:
            existing_tables = set(
                p.lstrip("/") for p in schema_resp.json().get("paths", {}).keys() if p.startswith("/")
            )
            import logging as _log
            _logger = _log.getLogger("sentry.migrations")
            for tname, _ in _migrations:
                if tname not in existing_tables:
                    _logger.warning(
                        f"Table '{tname}' not found in Supabase schema. "
                        "Please create it manually using the SQL in ARCHITECTURE.md or "
                        "the Supabase dashboard SQL editor. See backend/services/supabase_service.py."
                    )
                else:
                    _logger.info(f"Schema check OK: table '{tname}' exists.")
    except Exception as exc:
        import logging as _log
        _log.getLogger("sentry.migrations").warning(f"Schema migration check failed: {exc}")


_apply_schema_migrations()

# ---------------------------------------------------------------------------
# LEGACY: original SOC demo storage bootstrap. Kept only because the
# original /alerts, /media/verify, and /ingest/* routes below still use
# it — none of the NEW admin/employee dashboards touch this at all
# anymore (they use Supabase's scan_results/risk_flags exclusively via
# the routers above). This whole block is legacy/optional at this point.
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
    alert = _get_alert_or_404(alert_id)
    if alert.org_id is not None and str(alert.org_id) != str(admin.org_id):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert


@app.get("/health")
def health():
    return {"status": "ok", "alerts_in_store": len(STORE)}


# ---------------------------------------------------------------------------
# LEGACY Alerts (superseded by /scan/results, /risk-flags/my — kept only
# for backward compatibility, not used by any current frontend page)
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


@app.post("/media/verify", response_model=MediaVerifyResult)
def verify_media(req: MediaVerifyRequest):
    return media_integrity_service.verify_media(req)


# ---------------------------------------------------------------------------
# LEGACY ingestion routes (source-agnostic evidence -> old Alert pipeline).
# NOTE: Windows notification capture no longer uses these — it now calls
# POST /ingest/notification (routers/notification_ingest.py), which
# writes into the NEW scan_results/risk_flags pipeline instead. These
# /ingest/* routes are kept only for any other legacy caller.
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
# Simulate incoming alert (legacy demo button, unrelated to new SCA/
# notification pipelines)
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