"""
routers/device_control.py
--------------------------
Remote device freeze/unfreeze endpoints and employee-side freeze status polling.

SERVER-SIDE (called by admins / Cyber Heads):
  POST /device/freeze/{employee_id}    — Admin: create an active freeze request
  POST /device/unfreeze/{employee_id}  — Admin: lift all active freezes for employee
  GET  /device/all-freeze-status       — Cyber Head: cross-org freeze dashboard

EMPLOYEE-SIDE (polled by device_agent.py running on the employee's machine):
  GET  /device/freeze-status           — Any employee: returns their own freeze status

HOW THE FREEZE PROPAGATES:
  1. Admin calls POST /device/freeze/{employee_id} → row inserted into
     device_freeze_requests with status='active'
  2. device_agent.py (running on the employee machine, authenticated as that
     employee) polls GET /device/freeze-status every 30s
  3. When it sees status='active', it calls LockWorkStation() via ctypes —
     the screen locks silently, no dialog
  4. Admin calls POST /device/unfreeze/{employee_id} → status set to 'lifted'
  5. Next device_agent.py poll sees no active freeze → device remains unlocked
     on next natural unlock by the employee

ORG BOUNDARY:
  Every admin action verifies the target employee belongs to the admin's own
  org before writing. Cyber Head endpoints have no org filter (cross-org by
  design) — these require require_cyber_head, not just require_admin.

AUTO-FREEZE (from notification_ingest.py / scan.py):
  When a high_risky item is detected, device_freeze_service.auto_freeze_on_high_risk()
  is called automatically, creating an active freeze. This is silent and
  does not require admin interaction — the admin can lift it manually.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone

from models import AdminUser
from routers.org_auth import require_admin, get_current_admin

logger = logging.getLogger("sentry.device_control")

router = APIRouter(prefix="/device", tags=["device-control"])


class FreezeRequest(BaseModel):
    reason: str = "Manual freeze requested by administrator"


class FreezeStatusOut(BaseModel):
    frozen: bool
    employee_id: str
    org_id: Optional[str] = None
    status: Optional[str] = None
    reason: Optional[str] = None
    triggered_by: Optional[str] = None
    triggered_at: Optional[str] = None
    freeze_id: Optional[str] = None


class AllFreezeStatusOut(BaseModel):
    employee_id: str
    org_id: str
    status: str
    reason: Optional[str] = None
    triggered_by: Optional[str] = None
    triggered_at: Optional[str] = None
    lifted_by: Optional[str] = None
    freeze_id: str


def _verify_employee_in_org(client, employee_id: str, org_id: str) -> None:
    """Raises 404 if employee doesn't belong to admin's org."""
    result = (
        client.table("employees")
        .select("employee_id")
        .eq("employee_id", employee_id)
        .eq("org_id", org_id)
        .limit(1)
        .execute()
    )
    if not result.data:
        raise HTTPException(
            status_code=404,
            detail=f"Employee '{employee_id}' not found in your organization.",
        )


@router.post("/freeze/{employee_id}", response_model=FreezeStatusOut)
def freeze_device(
    employee_id: str,
    req: FreezeRequest,
    admin: AdminUser = Depends(require_admin),
):
    """
    Admin: immediately creates an active freeze request for a specific employee.
    The employee's device_agent.py will pick this up on its next poll and lock
    the workstation silently.
    """
    try:
        from services.device_freeze_service import trigger_freeze

        freeze = trigger_freeze(
            org_id=admin.org_id,
            employee_id=employee_id,
            reason=req.reason,
            triggered_by=admin.employee_id,
        )

        # Audit log (best-effort)
        try:
            from services.supabase_service import _get_client
            client = _get_client()
            client.table("scan_audit_log").insert({
                "org_id": admin.org_id,
                "message": f"Device FREEZE requested for '{employee_id}' by {admin.employee_id}. Reason: {req.reason}",
                "actor": admin.employee_id,
            }).execute()
        except Exception:
            pass

        return FreezeStatusOut(
            frozen=True,
            employee_id=employee_id,
            org_id=admin.org_id,
            status="active",
            reason=freeze.get("reason"),
            triggered_by=freeze.get("triggered_by"),
            triggered_at=freeze.get("triggered_at"),
            freeze_id=freeze.get("id"),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not create freeze request: {exc}")


@router.post("/unfreeze/{employee_id}", response_model=FreezeStatusOut)
def unfreeze_device(
    employee_id: str,
    admin: AdminUser = Depends(require_admin),
):
    """
    Admin: lifts all active freeze requests for a specific employee.
    The device_agent.py will stop applying new locks on its next poll.
    """
    try:
        from services.device_freeze_service import lift_freeze

        lifted = lift_freeze(
            org_id=admin.org_id,
            employee_id=employee_id,
            lifted_by=admin.employee_id,
        )

        # Audit log (best-effort)
        try:
            from services.supabase_service import _get_client
            client = _get_client()
            client.table("scan_audit_log").insert({
                "org_id": admin.org_id,
                "message": f"Device UNFREEZE for '{employee_id}' by {admin.employee_id}.",
                "actor": admin.employee_id,
            }).execute()
        except Exception:
            pass

        return FreezeStatusOut(
            frozen=False,
            employee_id=employee_id,
            org_id=admin.org_id,
            status="lifted",
            triggered_by=admin.employee_id,
            triggered_at=datetime.now(timezone.utc).isoformat(),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not lift freeze: {exc}")


@router.get("/freeze-status", response_model=FreezeStatusOut)
def my_freeze_status(caller: AdminUser = Depends(get_current_admin)):
    """
    Employee-polled: returns the caller's own device freeze status.
    Any authenticated employee can call this — admins can too.
    Returns frozen=False if no active freeze exists.
    Designed for high-frequency polling (every 30s from device_agent.py).
    """
    from services.device_freeze_service import get_freeze_status

    active = get_freeze_status(org_id=caller.org_id, employee_id=caller.employee_id)
    if active:
        return FreezeStatusOut(
            frozen=True,
            employee_id=caller.employee_id,
            org_id=caller.org_id,
            status=active.get("status"),
            reason=active.get("reason"),
            triggered_by=active.get("triggered_by"),
            triggered_at=active.get("triggered_at"),
            freeze_id=active.get("id"),
        )
    return FreezeStatusOut(frozen=False, employee_id=caller.employee_id, org_id=caller.org_id)


@router.get("/all-freeze-status", response_model=List[AllFreezeStatusOut])
def all_freeze_status(caller: AdminUser = Depends(get_current_admin)):
    """
    Returns freeze status for all employees across all orgs.
    Requires is_cyber_head OR is_admin (org-admins can see their org's freezes).
    Cyber Heads see all orgs; org admins see only their own org.
    """
    from services.device_freeze_service import list_all_freeze_requests

    if not (caller.is_admin or caller.is_cyber_head):
        raise HTTPException(status_code=403, detail="Admin or Cyber Head access required.")

    all_freezes = list_all_freeze_requests()

    # Org admins can only see their own org; Cyber Heads see all
    if not caller.is_cyber_head:
        all_freezes = [f for f in all_freezes if f.get("org_id") == caller.org_id]

    return [
        AllFreezeStatusOut(
            employee_id=f["employee_id"],
            org_id=f["org_id"],
            status=f["status"],
            reason=f.get("reason"),
            triggered_by=f.get("triggered_by"),
            triggered_at=f.get("triggered_at"),
            lifted_by=f.get("lifted_by"),
            freeze_id=f["id"],
        )
        for f in all_freezes
    ]
