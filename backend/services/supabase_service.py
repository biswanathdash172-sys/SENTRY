"""
services/supabase_service.py
-----------------------------
Replaces the previous local JSON-file org/admin store (db/org_store.py,
db/json_store.py, services/auth_service.py — all removed) with a real
Supabase-backed source of truth for organizations and employees.

WHY SUPABASE INSTEAD OF THE OLD LOCAL JSON STORE:
The earlier build kept orgs/admins in flat JSON files on disk
(db/orgs.json, db/admins.json) guarded by a file lock — fine for a single
demo machine, but not a real "connect your org" system. Supabase gives us
a real hosted Postgres table any teammate/judge can inspect, with the
same "never crash the demo" fail-safe philosophy as the rest of this
codebase: every function below catches connection/config errors and
raises a clearly-typed SupabaseAuthError instead of letting a raw
exception (or a 500) reach the judge's screen.

EXPECTED SUPABASE SCHEMA (create these two tables in the Supabase SQL
editor before running):

    create table organizations (
        org_id        text primary key,      -- the org-facing ID, e.g. "ACME-01"
        org_name      text not null,
        org_password  text not null,         -- preset password, plaintext by
                                              -- design for a hackathon demo;
                                              -- swap for a hashed column +
                                              -- verify_org_password() below
                                              -- if you want this production-safe
        created_at    timestamptz default now()
    );

    create table employees (
        employee_id   text primary key,      -- what the login page asks for
        org_id        text references organizations(org_id) not null,
        password      text not null,         -- preset password, same note as above
        display_name  text,
        created_at    timestamptz default now()
    );

Env vars required (see backend/.env.example):
    SUPABASE_URL
    SUPABASE_KEY   (the anon or service key — service key recommended for
                    server-side password checks so RLS can stay strict)
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

logger_prefix = "[supabase_service]"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

_client = None
_client_init_attempted = False


class SupabaseAuthError(Exception):
    """Raised for any org/employee auth failure — routers turn this into a
    clean 401/400/503, never a raw 500."""


class SupabaseNotConfigured(SupabaseAuthError):
    """Raised when SUPABASE_URL / SUPABASE_KEY aren't set. Kept as a
    distinct subclass so a router can show a friendlier "not configured
    yet" message during setup/demo rehearsal vs. a genuine bad-login 401."""


def _get_client():
    """Lazily creates and caches the Supabase client. Never raises on
    import — only when an org/employee lookup is actually attempted,
    matching db/database.py's "app must always boot" philosophy."""
    global _client, SUPABASE_URL, SUPABASE_KEY

    if _client is not None:
        return _client

    # Re-read env vars on every attempt (not just at import time) so a
    # fixed .env is picked up without needing a fresh process, and so we
    # never get permanently stuck on a stale empty value.
    SUPABASE_URL = os.environ.get("SUPABASE_URL", SUPABASE_URL)
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY", SUPABASE_KEY)

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise SupabaseNotConfigured(
            "SUPABASE_URL and SUPABASE_KEY must both be set (see backend/.env.example)."
        )
    try:
        from supabase import create_client  # local import: optional dependency
    except ImportError as exc:
        raise SupabaseNotConfigured(
            f"The 'supabase' package isn't installed ({exc}). Run: pip install supabase"
        ) from exc

    try:
        _client = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as exc:
        _client = None
        raise SupabaseNotConfigured(f"Could not create Supabase client: {exc}")

    return _client


@dataclass
class OrgRecord:
    org_id: str
    org_name: str


@dataclass
class EmployeeRecord:
    employee_id: str
    org_id: str
    display_name: Optional[str] = None


# ---------------------------------------------------------------------------
# "Get Access" step — org_id + org preset password -> proves this org is
# allowed to onboard. Does NOT log anyone in; it just unlocks the next step
# (creating/using an employee login) in the flow the product doc describes:
# admin/org connects once -> analyst dashboard activates.
# ---------------------------------------------------------------------------
def verify_org_access(org_id: str, org_password: str) -> OrgRecord:
    if not org_id or not org_password:
        raise SupabaseAuthError("Organization ID and password are both required.")

    client = _get_client()
    try:
        result = (
            client.table("organizations")
            .select("org_id, org_name, org_password")
            .eq("org_id", org_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise SupabaseAuthError(f"Could not reach Supabase: {exc}")

    rows = result.data or []
    if not rows:
        raise SupabaseAuthError("Unknown organization ID.")

    row = rows[0]
    # NOTE: plaintext-equality check, matching the "organizational preset
    # passwords" requirement. If you later hash org_password in Supabase,
    # swap this line for a bcrypt/argon2 verify call.
    if row.get("org_password") != org_password:
        raise SupabaseAuthError("Incorrect organization password.")

    return OrgRecord(org_id=row["org_id"], org_name=row.get("org_name", row["org_id"]))


# ---------------------------------------------------------------------------
# Employee login — employee_id + password -> which org they belong to.
# This is what backs the actual analyst-dashboard /login form.
# ---------------------------------------------------------------------------
def verify_employee_login(employee_id: str, password: str) -> EmployeeRecord:
    if not employee_id or not password:
        raise SupabaseAuthError("Employee ID and password are both required.")

    client = _get_client()
    try:
        result = (
            client.table("employees")
            .select("employee_id, org_id, password, display_name")
            .eq("employee_id", employee_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise SupabaseAuthError(f"Could not reach Supabase: {exc}")

    rows = result.data or []
    if not rows:
        raise SupabaseAuthError("Unknown employee ID.")

    row = rows[0]
    if row.get("password") != password:
        raise SupabaseAuthError("Incorrect password.")

    return EmployeeRecord(
        employee_id=row["employee_id"],
        org_id=row["org_id"],
        display_name=row.get("display_name"),
    )
