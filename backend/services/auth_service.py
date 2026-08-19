"""
services/auth_service.py
-------------------------
Real auth for org admins — bcrypt password hashing + JWT sessions.
Deliberately separate from the existing demo `/login` in main.py (which
stays exactly as-is for the analyst dashboard demo path).

Env vars:
  JWT_SECRET        Secret used to sign tokens. Falls back to a dev-only
                     default so local `uvicorn --reload` never fails to
                     boot — set a real one before deploying anywhere.
  JWT_EXPIRE_HOURS   Token lifetime in hours (default 12).
  ADMIN_INVITE_CODE  The invite code required by POST /admin/register.
                      Registration is rejected without a matching code —
                      this is what makes it "invite-only".
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt, JWTError
import bcrypt

from db import org_store
from models import AdminUser, Org

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-insecure-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = int(os.environ.get("JWT_EXPIRE_HOURS", "12"))
ADMIN_INVITE_CODE = os.environ.get("ADMIN_INVITE_CODE", "")

class AuthError(Exception):
    """Raised for any auth failure; routers translate this to HTTP 401/403."""


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_token(admin: AdminUser) -> str:
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=JWT_EXPIRE_HOURS)
    payload = {
        "sub": admin.username,
        "admin_id": admin.id,
        "org_id": admin.org_id,
        # jose expects a numeric (unix) timestamp for exp
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise AuthError(f"Invalid or expired token: {exc}")


def register_admin(invite_code: str, org_name: str, monitored_mailbox: str,
                    username: str, password: str) -> tuple[Org, AdminUser]:
    """Invite-only admin registration. Creates a new Org + its one Admin."""
    if not ADMIN_INVITE_CODE:
        raise AuthError("Admin registration is disabled: ADMIN_INVITE_CODE is not configured.")
    if invite_code != ADMIN_INVITE_CODE:
        raise AuthError("Invalid invite code.")
    if org_store.get_admin_by_username(username):
        raise AuthError(f"Username '{username}' is already taken.")
    if org_store.get_org_by_mailbox(monitored_mailbox):
        raise AuthError(f"An org already monitors mailbox '{monitored_mailbox}'.")

    org = org_store.create_org(name=org_name, monitored_mailbox=monitored_mailbox)
    # One-admin-per-org, enforced here even though we just created the org
    # (defensive — protects against a future code path that reuses an org).
    if org_store.admin_exists_for_org(org.id):
        raise AuthError("This org already has an admin.")
    admin = org_store.create_admin(org_id=org.id, username=username,
                                    password_hash=hash_password(password))
    return org, admin


def authenticate(username: str, password: str) -> AdminUser:
    admin = org_store.get_admin_by_username(username)
    if not admin or not verify_password(password, admin.password_hash):
        raise AuthError("Invalid username or password.")
    return admin


def get_admin_from_token(token: str) -> AdminUser:
    payload = decode_token(token)
    admin = org_store.get_admin_by_username(payload.get("sub", ""))
    if not admin:
        raise AuthError("Admin no longer exists.")
    return admin
