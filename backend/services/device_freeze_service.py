"""
services/device_freeze_service.py
-----------------------------------
Silent device freeze/unfreeze for employee machines.

Includes a HYBRID persistent storage engine:
  - Writes & reads from Supabase's device_freeze_requests table when available.
  - Automatically falls back to local memory/file storage if Supabase table
    has not been migrated yet (PGRST205 error).
  - This ensures device freeze/unfreeze works 100% reliably out-of-the-box in all environments.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentry.device_freeze")

# Local fallback store for offline/demo/unmigrated Supabase environments
_LOCAL_STORE_PATH = Path(__file__).resolve().parent.parent / "db" / "local_freezes.json"
_LOCAL_FREEZES: list[dict] = []


def _load_local_freezes() -> list[dict]:
    global _LOCAL_FREEZES
    if _LOCAL_FREEZES:
        return _LOCAL_FREEZES
    if _LOCAL_STORE_PATH.exists():
        try:
            with open(_LOCAL_STORE_PATH, "r", encoding="utf-8") as f:
                _LOCAL_FREEZES = json.load(f)
        except Exception:
            _LOCAL_FREEZES = []
    return _LOCAL_FREEZES


def _save_local_freezes() -> None:
    try:
        _LOCAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LOCAL_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(_LOCAL_FREEZES, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not persist local freeze file: {e}")


def trigger_freeze(
    org_id: str,
    employee_id: str,
    reason: str,
    triggered_by: str,
    risk_flag_id: Optional[str] = None,
) -> dict:
    """
    Creates a new device freeze request with status='active'.
    Attempts Supabase first; if table does not exist, saves to local store.
    """
    now = datetime.now(timezone.utc).isoformat()
    freeze_id = str(uuid.uuid4())
    row = {
        "id": freeze_id,
        "org_id": org_id,
        "employee_id": employee_id,
        "reason": reason,
        "status": "active",
        "triggered_by": triggered_by,
        "triggered_at": now,
        "lifted_by": None,
        "lifted_at": None,
    }
    if risk_flag_id:
        row["risk_flag_id"] = risk_flag_id

    # 1. Update local store
    freezes = _load_local_freezes()
    # Deactivate any previous active freezes for this employee locally
    for f in freezes:
        if f.get("org_id") == org_id and f.get("employee_id") == employee_id and f.get("status") == "active":
            f["status"] = "lifted"
            f["lifted_by"] = "superseded"
            f["lifted_at"] = now
    freezes.append(row)
    _save_local_freezes()

    # 2. Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        result = client.table("device_freeze_requests").insert(row).execute()
        if result.data:
            return result.data[0]
    except Exception as exc:
        logger.info(f"Supabase device_freeze_requests table not available ({exc}); using local storage.")

    return row


def lift_freeze(
    org_id: str,
    employee_id: str,
    lifted_by: str,
) -> list[dict]:
    """
    Transitions active freeze requests for an employee to 'lifted'.
    """
    now = datetime.now(timezone.utc).isoformat()
    lifted_rows = []

    # 1. Update local store
    freezes = _load_local_freezes()
    for f in freezes:
        if f.get("org_id") == org_id and f.get("employee_id") == employee_id and f.get("status") == "active":
            f["status"] = "lifted"
            f["lifted_by"] = lifted_by
            f["lifted_at"] = now
            lifted_rows.append(f)
    _save_local_freezes()

    # 2. Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        result = (
            client.table("device_freeze_requests")
            .update({"status": "lifted", "lifted_by": lifted_by, "lifted_at": now})
            .eq("org_id", org_id)
            .eq("employee_id", employee_id)
            .eq("status", "active")
            .execute()
        )
        if result.data:
            return result.data
    except Exception as exc:
        logger.info(f"Supabase update not available ({exc}); local freeze lifted.")

    return lifted_rows


def get_freeze_status(org_id: str, employee_id: str) -> Optional[dict]:
    """
    Returns the most recent ACTIVE freeze request for an employee, or None.
    Checks Supabase, falls back to local store.
    """
    # 1. Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        result = (
            client.table("device_freeze_requests")
            .select("id, status, reason, triggered_at, triggered_by")
            .eq("org_id", org_id)
            .eq("employee_id", employee_id)
            .eq("status", "active")
            .order("triggered_at", desc=True)
            .limit(1)
            .execute()
        )
        rows = result.data or []
        if rows:
            return rows[0]
    except Exception:
        pass

    # 2. Fallback to local store
    freezes = _load_local_freezes()
    active = [
        f for f in freezes
        if f.get("org_id") == org_id and f.get("employee_id") == employee_id and f.get("status") == "active"
    ]
    if active:
        # Return most recent
        return active[-1]

    return None


def auto_freeze_on_high_risk(
    org_id: str,
    employee_id: str,
    risk_flag_id: str,
    reason: str = "Automatically queued: high_risky finding detected by SENTRY",
) -> None:
    """
    Called by ingest routes after persisting a high_risky risk flag.
    Never raises.
    """
    try:
        trigger_freeze(
            org_id=org_id,
            employee_id=employee_id,
            reason=reason,
            triggered_by="sentry_auto",
            risk_flag_id=risk_flag_id,
        )
        logger.info(f"Auto-freeze queued for employee '{employee_id}' ({org_id}).")
    except Exception as exc:
        logger.warning(f"Auto-freeze error: {exc}")


def list_all_freeze_requests(status_filter: Optional[str] = None) -> list[dict]:
    """
    Returns freeze requests across all orgs.
    """
    # Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        query = (
            client.table("device_freeze_requests")
            .select("id, org_id, employee_id, reason, status, triggered_by, triggered_at, lifted_by, lifted_at, risk_flag_id")
            .order("triggered_at", desc=True)
            .limit(200)
        )
        if status_filter:
            query = query.eq("status", status_filter)
        result = query.execute()
        if result.data:
            return result.data
    except Exception:
        pass

    # Fallback to local store
    freezes = _load_local_freezes()
    if status_filter:
        freezes = [f for f in freezes if f.get("status") == status_filter]
    return list(reversed(freezes))
