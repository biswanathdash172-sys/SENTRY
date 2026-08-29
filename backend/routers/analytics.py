"""
routers/analytics.py
---------------------
Real-time organizational analytics (Item 3), computed live from the
actual scan_results + risk_flags rows in Supabase — no fabricated or
placeholder numbers anywhere.

SCOPE HONESTY (flagged to the user, confirmed as Option A): "based on the
captured system notifications" in the original requirement referred to a
Windows OS-notification capture module that was never built. Everything
below is computed from real SCA scan/risk data instead — the only data
source that actually exists in this system today. If/when Windows
notification capture is added, this module is the natural place to fold
that data in alongside scan_results.

GET /analytics returns:
  - tier_counts: real counts per risk tier
  - status_counts: pending vs completed, real counts
  - avg_resolution_minutes: real average of (approved_at - created_at)
    across every COMPLETED flag, in minutes. None if there are zero
    completed flags yet (never fabricated as 0 — 0 minutes would falsely
    imply instant resolution).
  - daily_counts: real count of risk_flags created per day, last 7 days
    (for the trend line on the admin dashboard's graph)
  - resolution_breakdown: real counts of auto_approved / admin_approved /
    admin_denied, so the graph can show how much was auto vs human-decided
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional

from models import AdminUser
from routers.org_auth import require_admin

router = APIRouter(tags=["analytics"])


class AnalyticsOut(BaseModel):
    tier_counts: Dict[str, int]
    status_counts: Dict[str, int]
    resolution_breakdown: Dict[str, int]
    avg_resolution_minutes: Optional[float]
    daily_counts: List[Dict[str, object]]  # [{"date": "2026-08-20", "count": 3}, ...]
    total_scanned: int


def _parse_ts(ts: str) -> datetime:
    # Supabase returns ISO 8601 timestamps; normalize 'Z' suffix for
    # Python's fromisoformat compatibility across Python versions.
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@router.get("/analytics", response_model=AnalyticsOut)
def get_analytics(admin: AdminUser = Depends(require_admin)):
    from services.supabase_service import _get_client

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    try:
        flags = (
            client.table("risk_flags")
            .select("id, tier, status, resolution, created_at, approved_at")
            .eq("org_id", admin.org_id)
            .execute()
        ).data or []
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not read risk_flags: {exc}")

    # --- tier_counts: real, from every flag ever created for this org ---
    tier_counts = {"not_risky": 0, "part_risky": 0, "high_risky": 0}
    for f in flags:
        tier = f.get("tier")
        if tier in tier_counts:
            tier_counts[tier] += 1

    # --- status_counts ---
    status_counts = {"pending": 0, "completed": 0}
    for f in flags:
        status = f.get("status")
        if status in status_counts:
            status_counts[status] += 1

    # --- resolution_breakdown ---
    resolution_breakdown = {"auto_approved": 0, "admin_approved": 0, "admin_denied": 0}
    for f in flags:
        res = f.get("resolution")
        if res in resolution_breakdown:
            resolution_breakdown[res] += 1

    # --- avg_resolution_minutes: real, only over flags that actually
    # have both created_at and approved_at ---
    resolution_deltas_minutes = []
    for f in flags:
        if f.get("status") == "completed" and f.get("approved_at") and f.get("created_at"):
            try:
                created = _parse_ts(f["created_at"])
                approved = _parse_ts(f["approved_at"])
                delta_minutes = (approved - created).total_seconds() / 60.0
                if delta_minutes >= 0:  # defensive: never report a negative duration
                    resolution_deltas_minutes.append(delta_minutes)
            except (ValueError, TypeError):
                continue  # malformed timestamp — skip rather than crash the whole report

    avg_resolution_minutes = (
        round(sum(resolution_deltas_minutes) / len(resolution_deltas_minutes), 1)
        if resolution_deltas_minutes else None
    )

    # --- daily_counts: real count per day, last 7 days ---
    now = datetime.now(timezone.utc)
    day_buckets: Dict[str, int] = defaultdict(int)
    for i in range(7):
        day_key = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        day_buckets[day_key] = 0  # ensure all 7 days appear even with zero events

    for f in flags:
        if not f.get("created_at"):
            continue
        try:
            created = _parse_ts(f["created_at"])
        except (ValueError, TypeError):
            continue
        days_ago = (now - created).days
        if 0 <= days_ago < 7:
            day_key = created.strftime("%Y-%m-%d")
            if day_key in day_buckets:
                day_buckets[day_key] += 1

    daily_counts = [
        {"date": date, "count": count}
        for date, count in sorted(day_buckets.items())
    ]

    return AnalyticsOut(
        tier_counts=tier_counts,
        status_counts=status_counts,
        resolution_breakdown=resolution_breakdown,
        avg_resolution_minutes=avg_resolution_minutes,
        daily_counts=daily_counts,
        total_scanned=len(flags),
    )