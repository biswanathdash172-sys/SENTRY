"""
services/supabase_service.py
-----------------------------
Replaces the previous local JSON-file org/admin store with a real
Supabase-backed source of truth for organizations and employees.

RBAC UPDATE (Option A, confirmed with the user): employees now carry an
is_admin flag. verify_employee_login() selects and returns it so
routers/org_auth.py can embed it in the JWT. create_employee() is the new
Employee Management write path — the org's FIRST employee is
automatically promoted to admin (enforced here via a count check, not
left to a manual DB edit), since every subsequent employee needs a real
admin identity to exist in the first place for this ordering to be safe.

EXPECTED SUPABASE SCHEMA (create/alter these before running):

    create table organizations (
        org_id        text primary key,
        org_name      text not null,
        org_password  text not null,
        created_at    timestamptz default now()
    );

    create table employees (
        employee_id   text primary key,
        org_id        text references organizations(org_id) not null,
        password      text not null,
        display_name  text,
        is_admin      boolean not null default false,   -- added: db/sca_schema.sql §5
        created_at    timestamptz default now()
    );

Env vars required (see backend/.env.example):
    SUPABASE_URL
    SUPABASE_KEY
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional, cast

logger_prefix = "[supabase_service]"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")

_client = None


class SupabaseAuthError(Exception):
    """Raised for any org/employee auth failure — routers turn this into a
    clean 401/400/503, never a raw 500."""


class SupabaseNotConfigured(SupabaseAuthError):
    """Raised when SUPABASE_URL / SUPABASE_KEY aren't set."""


def _get_client():
    global _client, SUPABASE_URL, SUPABASE_KEY

    if _client is not None:
        return _client

    SUPABASE_URL = os.environ.get("SUPABASE_URL", SUPABASE_URL)
    SUPABASE_KEY = os.environ.get("SUPABASE_KEY", SUPABASE_KEY)

    if not SUPABASE_URL or not SUPABASE_KEY:
        raise SupabaseNotConfigured(
            "SUPABASE_URL and SUPABASE_KEY must both be set (see backend/.env.example)."
        )
    try:
        from supabase import create_client
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
    is_admin: bool = False
    is_cyber_head: bool = False  # Cyber Head role — cross-org threat analyst access


# ---------------------------------------------------------------------------
# "Get Access" step — unchanged
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
    if row.get("org_password") != org_password:
        raise SupabaseAuthError("Incorrect organization password.")

    return OrgRecord(org_id=row["org_id"], org_name=row.get("org_name", row["org_id"]))


# ---------------------------------------------------------------------------
# Employee login — NOW selects is_admin too
# ---------------------------------------------------------------------------
def verify_employee_login(employee_id: str, password: str) -> EmployeeRecord:
    if not employee_id or not password:
        raise SupabaseAuthError("Employee ID and password are both required.")

    client = _get_client()

    # Try with is_cyber_head first; if the column doesn't exist yet (migration
    # pending), fall back to the old query without it. This allows the server
    # to boot and authenticate correctly even before the v0.6.0 migration is applied.
    for select_cols in (
        "employee_id, org_id, password, display_name, is_admin, is_cyber_head",
        "employee_id, org_id, password, display_name, is_admin",
    ):
        try:
            result = (
                client.table("employees")
                .select(select_cols)
                .eq("employee_id", employee_id)
                .limit(1)
                .execute()
            )
            break  # Succeeded — exit the retry loop
        except Exception as exc:
            err_str = str(exc)
            if "is_cyber_head" in err_str and "does not exist" in err_str:
                # Migration not yet applied — retry without the new column
                import logging as _log
                _log.getLogger("sentry.supabase").warning(
                    "is_cyber_head column not found — migration_v0.6.0.sql not yet applied. "
                    "Falling back to login without Cyber Head role. "
                    "Apply the migration from backend/db/migration_v0.6.0.sql."
                )
                continue
            raise SupabaseAuthError(f"Could not reach Supabase: {exc}")
    else:
        raise SupabaseAuthError("Could not reach Supabase.")

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
        is_admin=bool(row.get("is_admin", False)),
        is_cyber_head=bool(row.get("is_cyber_head", False)),
    )


# ---------------------------------------------------------------------------
# NEW: Employee Management — real write path, admin-gated in the router.
# ---------------------------------------------------------------------------
def create_employee(
    org_id: str,
    employee_id: str,
    name: str,
    password: str,
) -> EmployeeRecord:
    """
    Creates a new employee row for an org. FAIL-SAFE ADMIN BOOTSTRAP: the
    very first employee ever created for a given org_id is automatically
    made is_admin=true (checked via a real count query against Supabase,
    not assumed) — every org needs exactly one real admin identity to
    exist before any admin-gated route can be used at all, and this is
    the only safe moment to grant it automatically. Every employee after
    the first is is_admin=false by default; promoting anyone further
    requires an existing admin's action (not built as a self-service
    "make me admin" route — that would defeat the purpose of RBAC).

    Raises SupabaseAuthError on duplicate employee_id or any DB failure —
    a write failure here must be visible to the caller (the admin doing
    the creating), never silently swallowed.
    """
    if not org_id or not employee_id or not name or not password:
        raise SupabaseAuthError("org_id, employee_id, name, and password are all required.")

    client = _get_client()

    try:
        existing = (
            client.table("employees")
            .select("employee_id")
            .eq("employee_id", employee_id)
            .limit(1)
            .execute()
        )
        if existing.data:
            raise SupabaseAuthError(f"Employee ID '{employee_id}' already exists.")

        count_result = (
            client.table("employees")
            .select("employee_id", count=cast(Any, "exact"))
            .eq("org_id", org_id)
            .execute()
        )
        is_first_employee = (count_result.count or 0) == 0

        insert_row = {
            "employee_id": employee_id,
            "org_id": org_id,
            "display_name": name,
            "password": password,  # NOTE: plaintext, matching organizations.org_password's
                                    # existing pattern in this codebase — see this file's
                                    # top-level docstring note about hashing later.
            "is_admin": is_first_employee,
        }
        insert_result = client.table("employees").insert(insert_row).execute()
        if not insert_result.data:
            raise SupabaseAuthError("Insert succeeded but returned no row — unexpected Supabase response.")

        row = insert_result.data[0]
        return EmployeeRecord(
            employee_id=row["employee_id"],
            org_id=row["org_id"],
            display_name=row.get("display_name"),
            is_admin=bool(row.get("is_admin", False)),
        )
    except SupabaseAuthError:
        raise
    except Exception as exc:
        raise SupabaseAuthError(f"Could not create employee: {exc}")


# ---------------------------------------------------------------------------
# NEW: Advanced employee/role management (Item 1).
# ---------------------------------------------------------------------------
def list_employees(org_id: str) -> list[EmployeeRecord]:
    """Real Supabase read — every employee belonging to this org."""
    client = _get_client()
    try:
        result = (
            client.table("employees")
            .select("employee_id, org_id, display_name, is_admin")
            .eq("org_id", org_id)
            .order("employee_id")
            .execute()
        )
    except Exception as exc:
        raise SupabaseAuthError(f"Could not list employees: {exc}")

    return [
        EmployeeRecord(
            employee_id=row["employee_id"],
            org_id=row["org_id"],
            display_name=row.get("display_name"),
            is_admin=bool(row.get("is_admin", False)),
        )
        for row in (result.data or [])
    ]


def count_org_admins(org_id: str) -> int:
    """Used as a fail-safe check before any demotion/deletion that could
    leave an org with zero admins — a real count query, not an assumption."""
    client = _get_client()
    try:
        result = (
            client.table("employees")
            .select("employee_id", count=cast(Any, "exact"))
            .eq("org_id", org_id)
            .eq("is_admin", True)
            .execute()
        )
        return result.count or 0
    except Exception as exc:
        raise SupabaseAuthError(f"Could not count org admins: {exc}")


def set_employee_admin_status(org_id: str, employee_id: str, is_admin: bool) -> EmployeeRecord:
    """
    Promotes or revokes admin status for one employee. FAIL-SAFE: if this
    is a REVOKE (is_admin=False) and the target is currently the org's
    LAST remaining admin, this raises rather than proceeding — an org
    with zero admins can never manage itself again, so this must never
    be allowed to happen silently. The caller (router) still enforces its
    own "can't demote yourself if you're the last admin" UX-level check;
    this is the authoritative, DB-backed guarantee underneath it.
    """
    client = _get_client()

    try:
        existing = (
            client.table("employees")
            .select("employee_id, org_id, is_admin")
            .eq("employee_id", employee_id)
            .eq("org_id", org_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise SupabaseAuthError(f"Could not look up employee: {exc}")

    rows = existing.data or []
    if not rows:
        raise SupabaseAuthError(f"Employee '{employee_id}' not found in this organization.")

    target = rows[0]
    if not is_admin and bool(target.get("is_admin")):
        remaining_admins = count_org_admins(org_id)
        if remaining_admins <= 1:
            raise SupabaseAuthError(
                "Cannot revoke admin status: this is the organization's last "
                "remaining admin. Promote another employee to admin first."
            )

    try:
        result = (
            client.table("employees")
            .update({"is_admin": is_admin})
            .eq("employee_id", employee_id)
            .eq("org_id", org_id)
            .execute()
        )
    except Exception as exc:
        raise SupabaseAuthError(f"Could not update admin status: {exc}")

    if not result.data:
        raise SupabaseAuthError("Update succeeded but returned no row — unexpected Supabase response.")

    row = result.data[0]
    return EmployeeRecord(
        employee_id=row["employee_id"],
        org_id=row["org_id"],
        display_name=row.get("display_name"),
        is_admin=bool(row.get("is_admin", False)),
    )


def delete_employee(org_id: str, employee_id: str) -> None:
    """
    Removes an employee. FAIL-SAFE: refuses to delete an org's last
    remaining admin, same reasoning as set_employee_admin_status above —
    an org must never be left with zero admins as a side effect of a
    deletion.
    """
    client = _get_client()

    try:
        existing = (
            client.table("employees")
            .select("employee_id, is_admin")
            .eq("employee_id", employee_id)
            .eq("org_id", org_id)
            .limit(1)
            .execute()
        )
    except Exception as exc:
        raise SupabaseAuthError(f"Could not look up employee: {exc}")

    rows = existing.data or []
    if not rows:
        raise SupabaseAuthError(f"Employee '{employee_id}' not found in this organization.")

    if bool(rows[0].get("is_admin")):
        remaining_admins = count_org_admins(org_id)
        if remaining_admins <= 1:
            raise SupabaseAuthError(
                "Cannot remove this employee: they are the organization's last "
                "remaining admin. Promote another employee to admin first."
            )

    try:
        client.table("employees").delete().eq("employee_id", employee_id).eq("org_id", org_id).execute()
    except Exception as exc:
        raise SupabaseAuthError(f"Could not delete employee: {exc}")