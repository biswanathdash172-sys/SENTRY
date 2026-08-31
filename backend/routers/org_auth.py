"""
routers/org_auth.py
--------------------
Org/employee access flow, backed by Supabase.

  1. POST /access/verify-org   - "Get Access" page: org_id + org_password
     checked against Supabase's `organizations` table.
  2. POST /login                - Employee ID + password checked against
     Supabase's `employees` table. Returns a signed JWT.

SELF-CONTAINED JWT (no import from a separate top-level auth.py):
this file used to do `from auth import create_access_token, ...`, which
broke if backend/auth.py wasn't present or wasn't on sys.path depending
on how uvicorn was launched (e.g. `uvicorn main:app` run from inside
backend/ vs from the project root). To remove that fragility entirely,
the JWT create/verify logic (stdlib-only HS256, same approach as before)
now lives directly in this file.

RISK-CLASSIFIER HOOK (new): the first time an org successfully verifies
via /access/verify-org, we ensure its auto_approval_rules defaults exist
in Supabase (not_risky=auto, part_risky=manual, high_risky=manual —
non-negotiable). This is the "org creation" moment for our purposes,
since this codebase has no separate org-registration route — org rows
already exist in Supabase (created directly there per
services/supabase_service.py's schema), and the first verify-org call is
the first time SENTRY-side code is aware of that org. ensure_default_rules()
is idempotent (upsert) and NEVER raises, so a Supabase hiccup here can
never break the login flow itself — see risk_classifier.py's docstring
for the full fail-safe reasoning.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time

from fastapi import APIRouter, HTTPException, Header, Form, Depends
from pydantic import BaseModel

from services.supabase_service import (
    verify_org_access,
    verify_employee_login,
    SupabaseAuthError,
    SupabaseNotConfigured,
)
from services.risk_classifier import ensure_default_rules
from models import AdminUser

logger = logging.getLogger("sentry.org_auth")

router = APIRouter(tags=["org-auth"])

# ---------------------------------------------------------------------------
# Minimal stdlib HS256 JWT (no PyJWT/jose dependency needed)
# ---------------------------------------------------------------------------
JWT_SECRET = os.environ.get("JWT_SECRET", "sentry-demo-insecure-secret-change-me")
JWT_EXPIRY_SECONDS = int(os.environ.get("JWT_EXPIRY_SECONDS", str(24 * 60 * 60)))


class TokenError(Exception):
    pass


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def create_access_token(subject: str, extra_claims: dict | None = None) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": subject, "iat": now, "exp": now + JWT_EXPIRY_SECONDS, **(extra_claims or {})}
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_b64}.{payload_b64}.{_b64url_encode(signature)}"


def decode_access_token(token: str) -> dict:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError:
        raise TokenError("Malformed token")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        actual_sig = _b64url_decode(signature_b64)
    except Exception:
        raise TokenError("Malformed token signature")
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise TokenError("Invalid token signature")

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception:
        raise TokenError("Malformed token payload")

    if payload.get("exp", 0) < int(time.time()):
        raise TokenError("Token expired")
    return payload


# ---------------------------------------------------------------------------
# Step 1 - "Get Access": validate org_id + org preset password
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
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    # NEW: first successful verification for this org -> make sure its
    # auto_approval_rules defaults exist. Idempotent, never raises — a
    # failure here is logged and swallowed, never surfaced to the org as
    # a login error (see risk_classifier.ensure_default_rules docstring).
    try:
        ensure_default_rules(org.org_id)
    except Exception as exc:
        # Belt-and-suspenders: ensure_default_rules() already catches its
        # own errors internally and never raises, but if that contract
        # ever changes, this outer catch guarantees /access/verify-org
        # still can't be broken by a risk-rules problem.
        logger.warning(f"ensure_default_rules raised unexpectedly for org "
                        f"'{org.org_id}' ({exc}) — continuing login anyway.")

    return OrgAccessResponse(status="ok", org_id=org.org_id, org_name=org.org_name)


# Sentinel used as the "employee_id" for an org-level (not per-employee)
# login. Chosen to be impossible to collide with a real employee_id
# (Supabase's employees.employee_id is admin-chosen text — this is
# reserved and documented so no one ever creates a real employee with
# this exact id). Self-action guards elsewhere (e.g. "can't remove your
# own account") naturally never trigger for this sentinel, which is
# correct: an org login isn't a row in the employees table at all.
ORG_LOGIN_SENTINEL_EMPLOYEE_ID = "__ORG_ACCOUNT__"


class OrgLoginRequest(BaseModel):
    org_id: str
    org_password: str


@router.post("/org-login")
def org_login(req: OrgLoginRequest):
    """
    Real Organization-level login (Item 3): verifies org_id + org_password
    against Supabase exactly like /access/verify-org, but ALSO issues a
    usable JWT — so the org itself (not any specific employee) can call
    admin-gated endpoints like /employees directly. This is the new
    unified-login path the main login page now offers alongside Employee
    ID + password.

    The issued token carries is_org=true and org_id, with NO employee_id
    claim — get_current_admin() below maps this to an AdminUser with
    employee_id=ORG_LOGIN_SENTINEL_EMPLOYEE_ID and is_admin=True, so all
    existing employee-management/admin-gated routes work unchanged.
    """
    try:
        org = verify_org_access(req.org_id, req.org_password)
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    try:
        ensure_default_rules(org.org_id)
    except Exception as exc:
        logger.warning(f"ensure_default_rules raised unexpectedly for org "
                        f"'{org.org_id}' ({exc}) — continuing login anyway.")

    token = create_access_token(
        subject=org.org_id,
        extra_claims={"org_id": org.org_id, "is_org": True},
    )
    return {
        "status": "ok",
        "org_id": org.org_id,
        "org_name": org.org_name,
        "is_org": True,
        "token": token,
    }


# ---------------------------------------------------------------------------
# Step 2 - Employee login
# ---------------------------------------------------------------------------
@router.post("/login")
def employee_login(employee_id: str = Form(...), password: str = Form(...)):
    try:
        employee = verify_employee_login(employee_id, password)
    except SupabaseNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except SupabaseAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    # RBAC (Option A): is_admin is baked into the JWT at login time, sourced
    # directly from Supabase's employees.is_admin column — never trust a
    # client-supplied role, always re-derive it server-side from the DB.
    # is_cyber_head follows the same pattern.
    token = create_access_token(
        subject=employee.employee_id,
        extra_claims={
            "org_id": employee.org_id,
            "employee_id": employee.employee_id,
            "is_admin": employee.is_admin,
            "is_cyber_head": getattr(employee, "is_cyber_head", False),
        },
    )
    return {
        "status": "ok",
        "employee_id": employee.employee_id,
        "org_id": employee.org_id,
        "is_admin": employee.is_admin,
        "is_cyber_head": getattr(employee, "is_cyber_head", False),
        "token": token,
    }


# ---------------------------------------------------------------------------
# Dependency used by main.py's org-gated routes
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
    if not org_id:
        raise HTTPException(status_code=401, detail="Token missing org claim.")

    # ORG-LEVEL LOGIN: no employee_id claim at all, just is_org=true.
    # Mapped to a sentinel employee_id + is_admin=True so every existing
    # admin-gated route (employees, scan, rules, analytics, reports)
    # works for an org login without any route-level changes.
    if payload.get("is_org"):
        return AdminUser(employee_id=ORG_LOGIN_SENTINEL_EMPLOYEE_ID, org_id=org_id, is_admin=True)

    employee_id = payload.get("employee_id") or payload.get("sub")
    if not employee_id:
        raise HTTPException(status_code=401, detail="Token missing employee claim.")

    # FAIL CLOSED: if an older token (issued before this RBAC update) has
    # no is_admin claim at all, default to False rather than trusting an
    # absence of the field as "admin". Same fail-safe direction as
    # risk_classifier.py's "unknown -> treat as the more restrictive case."
    is_admin = bool(payload.get("is_admin", False))
    is_cyber_head = bool(payload.get("is_cyber_head", False))

    return AdminUser(employee_id=employee_id, org_id=org_id, is_admin=is_admin, is_cyber_head=is_cyber_head)


def require_admin(admin: AdminUser = Depends(get_current_admin)) -> AdminUser:
    """
    Second-layer dependency for routes that must be admin-only. Layered on
    top of get_current_admin (which only proves "this is a valid logged-in
    employee of this org") rather than duplicating its logic, so there is
    exactly one place that decodes/validates the JWT itself.
    """
    if not admin.is_admin:
        raise HTTPException(
            status_code=403,
            detail="This action requires an organization admin account.",
        )
    return admin


def require_cyber_head(caller: AdminUser = Depends(get_current_admin)) -> AdminUser:
    """
    Third-layer dependency for Cyber Head-only routes. Cyber Heads have
    cross-org visibility — this must never be granted based on is_admin
    alone. A Cyber Head who is ALSO an admin satisfies both.
    """
    if not caller.is_cyber_head:
        raise HTTPException(
            status_code=403,
            detail="This endpoint requires Cyber Head access.",
        )
    return caller