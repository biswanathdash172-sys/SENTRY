"""
routers/cyber_head.py
----------------------
Cyber Head portal endpoints — cross-org threat monitoring.

ALL routes in this file require is_cyber_head=True in the JWT.
An org-level admin cannot access these even if they somehow know the URL.

  GET /cyber/threats       — Cross-org high-risk flag summary
  GET /cyber/devices       — All employees + their freeze status across all orgs
  GET /cyber/email-feed    — Recent email risk events across all orgs
  GET /cyber/orgs          — List all organisations
  GET /cyber/stats         — Dashboard KPIs: total flags, active freezes, open orgs
"""

from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from datetime import datetime, timezone

from models import AdminUser
from routers.org_auth import get_current_admin

logger = logging.getLogger("sentry.cyber_head")

router = APIRouter(prefix="/cyber", tags=["cyber-head"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------

def require_cyber_head(caller: AdminUser = Depends(get_current_admin)) -> AdminUser:
    """
    Second-layer dependency: ensures the caller has is_cyber_head=True.
    Layered on top of get_current_admin (which already validates the JWT)
    rather than duplicating JWT decode logic.
    """
    if not caller.is_cyber_head:
        raise HTTPException(
            status_code=403,
            detail="This endpoint requires Cyber Head access.",
        )
    return caller


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class OrgOut(BaseModel):
    org_id: str
    org_name: Optional[str] = None
    created_at: Optional[str] = None
    employee_count: Optional[int] = None
    high_risk_count: Optional[int] = None


class ThreatFlagOut(BaseModel):
    id: str
    org_id: str
    employee_id: Optional[str] = None
    tier: str
    status: str
    source_type: Optional[str] = None
    notification_text: Optional[str] = None
    created_at: Optional[str] = None
    approved_by: Optional[str] = None


class DeviceStatusOut(BaseModel):
    employee_id: str
    org_id: str
    is_frozen: bool
    freeze_reason: Optional[str] = None
    freeze_triggered_by: Optional[str] = None
    freeze_triggered_at: Optional[str] = None


class EmailThreatOut(BaseModel):
    id: str
    org_id: str
    employee_id: Optional[str] = None
    notification_text: Optional[str] = None
    tier: str
    status: str
    created_at: Optional[str] = None


class CyberStatsOut(BaseModel):
    total_high_risk_flags: int
    total_active_freezes: int
    total_orgs: int
    total_employees: int
    pending_reviews: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/stats", response_model=CyberStatsOut)
def cyber_stats(cyber: AdminUser = Depends(require_cyber_head)):
    """Dashboard KPIs for the Cyber Head portal header."""
    try:
        from services.supabase_service import _get_client
        client = _get_client()

        # High risk flags
        hr = client.table("risk_flags").select("id", count="exact") \
            .eq("tier", "high_risky").execute()
        total_high = hr.count or 0

        # Active freezes
        fr = client.table("device_freeze_requests").select("id", count="exact") \
            .eq("status", "active").execute()
        total_frozen = fr.count or 0

        # Orgs
        orgs = client.table("organizations").select("org_id", count="exact").execute()
        total_orgs = orgs.count or 0

        # Employees
        emps = client.table("employees").select("employee_id", count="exact").execute()
        total_emps = emps.count or 0

        # Pending reviews (risk_flags with status=pending)
        pending = client.table("risk_flags").select("id", count="exact") \
            .eq("status", "pending").execute()
        total_pending = pending.count or 0

        return CyberStatsOut(
            total_high_risk_flags=total_high,
            total_active_freezes=total_frozen,
            total_orgs=total_orgs,
            total_employees=total_emps,
            pending_reviews=total_pending,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Stats unavailable: {exc}")


@router.get("/orgs", response_model=List[OrgOut])
def list_orgs(cyber: AdminUser = Depends(require_cyber_head)):
    """All organisations registered in SENTRY."""
    try:
        from services.supabase_service import _get_client
        client = _get_client()

        result = client.table("organizations") \
            .select("org_id, org_name, created_at") \
            .order("created_at", desc=True) \
            .execute()

        orgs = result.data or []

        # Enrich with employee counts and high-risk counts
        out = []
        for org in orgs:
            oid = org["org_id"]
            try:
                emp_count = client.table("employees").select("employee_id", count="exact") \
                    .eq("org_id", oid).execute()
                hr_count = client.table("risk_flags").select("id", count="exact") \
                    .eq("org_id", oid).eq("tier", "high_risky").execute()
                out.append(OrgOut(
                    org_id=oid,
                    org_name=org.get("org_name"),
                    created_at=org.get("created_at"),
                    employee_count=emp_count.count or 0,
                    high_risk_count=hr_count.count or 0,
                ))
            except Exception:
                out.append(OrgOut(org_id=oid, org_name=org.get("org_name")))

        return out
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not list orgs: {exc}")


@router.get("/threats", response_model=List[ThreatFlagOut])
def cross_org_threats(
    tier: Optional[str] = Query(default=None, description="Filter by tier: not_risky, part_risky, high_risky"),
    status: Optional[str] = Query(default=None, description="Filter by status: pending, completed"),
    limit: int = Query(default=50, ge=1, le=200),
    cyber: AdminUser = Depends(require_cyber_head),
):
    """All risk flags across all orgs, optionally filtered by tier/status."""
    try:
        from services.supabase_service import _get_client
        client = _get_client()

        query = client.table("risk_flags") \
            .select("id, org_id, employee_id, tier, status, source_type, notification_text, created_at, approved_by") \
            .order("created_at", desc=True) \
            .limit(limit)

        if tier:
            query = query.eq("tier", tier)
        if status:
            query = query.eq("status", status)

        result = query.execute()
        return [
            ThreatFlagOut(
                id=r["id"], org_id=r["org_id"],
                employee_id=r.get("employee_id"),
                tier=r["tier"], status=r["status"],
                source_type=r.get("source_type"),
                notification_text=(r.get("notification_text") or "")[:200],
                created_at=r.get("created_at"),
                approved_by=r.get("approved_by"),
            )
            for r in (result.data or [])
        ]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not fetch threats: {exc}")


@router.get("/devices", response_model=List[DeviceStatusOut])
def all_device_status(cyber: AdminUser = Depends(require_cyber_head)):
    """
    All employees across all orgs with their current freeze status.
    Non-frozen employees show is_frozen=False.
    """
    try:
        from services.supabase_service import _get_client
        client = _get_client()

        # All employees
        emp_result = client.table("employees") \
            .select("employee_id, org_id") \
            .order("org_id") \
            .execute()
        employees = emp_result.data or []

        # All active freezes
        freeze_result = client.table("device_freeze_requests") \
            .select("employee_id, org_id, reason, triggered_by, triggered_at") \
            .eq("status", "active") \
            .execute()
        # Build lookup: (org_id, employee_id) -> freeze record
        freeze_map: dict[tuple, dict] = {}
        for f in (freeze_result.data or []):
            key = (f["org_id"], f["employee_id"])
            if key not in freeze_map:  # take most recent (ordered by insert order)
                freeze_map[key] = f

        out = []
        for emp in employees:
            key = (emp["org_id"], emp["employee_id"])
            freeze = freeze_map.get(key)
            out.append(DeviceStatusOut(
                employee_id=emp["employee_id"],
                org_id=emp["org_id"],
                is_frozen=bool(freeze),
                freeze_reason=freeze.get("reason") if freeze else None,
                freeze_triggered_by=freeze.get("triggered_by") if freeze else None,
                freeze_triggered_at=freeze.get("triggered_at") if freeze else None,
            ))

        return out
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not fetch device status: {exc}")


@router.get("/email-feed", response_model=List[EmailThreatOut])
def cross_org_email_feed(
    limit: int = Query(default=50, ge=1, le=200),
    cyber: AdminUser = Depends(require_cyber_head),
):
    """All email-sourced risk events across all orgs, most recent first."""
    try:
        from services.supabase_service import _get_client
        client = _get_client()

        result = client.table("risk_flags") \
            .select("id, org_id, employee_id, notification_text, tier, status, created_at") \
            .eq("source_type", "email") \
            .order("created_at", desc=True) \
            .limit(limit) \
            .execute()

        return [
            EmailThreatOut(
                id=r["id"],
                org_id=r["org_id"],
                employee_id=r.get("employee_id"),
                notification_text=(r.get("notification_text") or "")[:300],
                tier=r["tier"],
                status=r["status"],
                created_at=r.get("created_at"),
            )
            for r in (result.data or [])
        ]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Could not fetch email feed: {exc}")
