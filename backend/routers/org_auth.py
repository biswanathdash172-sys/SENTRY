"""
routers/org_auth.py
--------------------
Replaces routers/admin_auth.py (deleted). Two-step access flow, matching
the requested product flow exactly:

  1. POST /access/verify-org
     "Get Access" page — org_id + org_password checked against Supabase's
     `organizations` table. Does not log anyone in; it just confirms this
     organization is real and known, and unlocks the login page.

  2. POST /login
     The actual analyst-dashboard sign-in — employee_id + password
     checked against Supabase's `employees` table (which also carries
     org_id). On success returns a signed JWT the frontend stores and
     sends as `Authorization: Bearer <token>` on every /alerts call, so
     alerts stay scoped to the employee's org (see main.py's
     _get_org_alert_or_404).

JWT issuance/verification reuses backend/auth.py's existing hand-rolled
HS256 implementation (stdlib-only, already used elsewhere in this repo) —
no new JWT dependency introduced for this refactor.
"""

from fastapi import APIRouter, HTTPException, Header, Form
from pydantic import BaseModel

from auth import create_access_token, decode_access_token, TokenError
from services.supabase_service import (
    verify_org_access,
    verify_employee_login,
    SupabaseAuthError,
    SupabaseNotConfigured,
)
from models import AdminUser

router = APIRouter(tags=["org-auth"])


# ---------------------------------------------------------------------------
# Step 1 — "Get Access": validate org_id + org preset password
# ---------------------------------------------------------------------------
class OrgAccessRequest(BaseModel):
    org_id: str
    org_password: str


class OrgAccessResponse(BaseModel):
    status: str
    org_id: str
    org_name: str


@router.post("/access/verify-org", response_model=OrgAccessResponse)
def verify_org(req: OrgAccessRequest):
    try:
        org = verify_org_access(req.org_id, req.org_password)
    except SupabaseNotConfigured as exc:
        # Distinct 503 (not 401) — this means Supabase isn't wired up yet,
        # not that the credentials were wrong. Never disguise a config
        # problem as a bad-password error.
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    return OrgAccessResponse(status="ok", org_id=org.org_id, org_name=org.org_name)


# ---------------------------------------------------------------------------
# Step 2 — Employee login (the real /login used by the dashboard form)
# ---------------------------------------------------------------------------
@router.post("/login")
def employee_login(employee_id: str = Form(...), password: str = Form(...)):
    """
    Same request shape the frontend already posts (Form fields), just
    renamed from `username` to `employee_id` and now backed by Supabase
    instead of the demo "accept anything" stub / the old local user store.
    """
    try:
        employee = verify_employee_login(employee_id, password)
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    token = create_access_token(
        subject=employee.employee_id,
        extra_claims={"org_id": employee.org_id, "employee_id": employee.employee_id},
    )
    return {
        "status": "ok",
        "employee_id": employee.employee_id,
        "org_id": employee.org_id,
        "token": token,
    }


# ---------------------------------------------------------------------------
# Dependency used by main.py's org-gated routes (GET /alerts, approve/deny,
# etc.) — decodes the JWT issued above and returns an AdminUser-shaped
# object carrying org_id, so existing gating logic in main.py needs no
# further changes beyond the import path.
# ---------------------------------------------------------------------------
def get_current_admin(authorization: str | None = Header(default=None)) -> AdminUser:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token.")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = decode_access_token(token)
    except TokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    org_id = payload.get("org_id")
    employee_id = payload.get("employee_id") or payload.get("sub")
    if not org_id or not employee_id:
        raise HTTPException(status_code=401, detail="Token missing org/employee claims.")

    return AdminUser(employee_id=employee_id, org_id=org_id)
