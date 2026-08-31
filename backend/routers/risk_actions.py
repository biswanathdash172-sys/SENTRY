"""
routers/risk_actions.py
-------------------------
Actionable risk resolution (Item 2): real Approve/Deny on any risk_flags
row, admin-only. Directly updates risk_flags.status/resolution/approved_by
in Supabase, writes a scan_audit_log entry, and is immediately visible on
the employee's own dashboard (GET /risk-flags/my — already polling every
8s, so no extra wiring needed there; it just reflects the updated row).

  POST /risk-flags/{flag_id}/approve
  POST /risk-flags/{flag_id}/deny

ORG BOUNDARY: every action re-fetches the flag and verifies its org_id
matches the calling admin's own org_id before allowing any write — an
admin from Org A can never approve/deny a flag belonging to Org B, even
if they somehow know its UUID.

NOTE ON HIGH_RISKY: manual admin approval of a high_risky flag is
explicitly ALLOWED here — the non-negotiable rule from risk_classifier.py
and sca_schema.sql's CHECK constraints is specifically that the SYSTEM
can never AUTO-approve high_risky. A human admin making an informed,
logged decision is exactly what "human-governed" means; that's the whole
point of the fail-safe existing in the first place.
"""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from models import AdminUser
from routers.org_auth import require_admin

router = APIRouter(tags=["risk-actions"])


class RiskFlagActionOut(BaseModel):
    id: str
    status: str
    resolution: str
    approved_by: str
    approved_at: str


def _get_flag_or_404(client, flag_id: str, org_id: str) -> dict:
    result = (
        client.table("risk_flags")
        .select("id, org_id, status, tier")
        .eq("id", flag_id)
        .limit(1)
        .execute()
    )
    rows = result.data or []
    if not rows:
        raise HTTPException(status_code=404, detail=f"Risk flag '{flag_id}' not found.")
    flag = rows[0]
    if str(flag["org_id"]) != str(org_id):
        # Same 404 (not 403) as SENTRY's existing _get_org_alert_or_404
        # pattern in main.py — don't leak that the flag exists at all to
        # a caller outside its org.
        raise HTTPException(status_code=404, detail=f"Risk flag '{flag_id}' not found.")
    return flag


def _resolve_flag(flag_id: str, admin: AdminUser, resolution: str) -> RiskFlagActionOut:
    from services.supabase_service import _get_client

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    flag = _get_flag_or_404(client, flag_id, admin.org_id)

    from services.risk_actions_state import ALLOWED_TRANSITIONS

    if resolution not in ALLOWED_TRANSITIONS.get(flag.get("status", "pending"), set()):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid transition from {flag.get('status')} to {resolution}"
        )

    if flag["status"] == "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Risk flag '{flag_id}' has already been resolved "
                   f"(status is already 'completed').",
        )

    now = datetime.now(timezone.utc).isoformat()
    try:
        update_result = (
            client.table("risk_flags")
            .update({
                "status": "completed",
                "resolution": resolution,
                "approved_by": admin.employee_id,
                "approved_at": now,
            })
            .eq("id", flag_id)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not update risk flag: {exc}")

    if not update_result.data:
        raise HTTPException(status_code=500, detail="Update returned no row — unexpected Supabase response.")

    updated = update_result.data[0]

    verb = "APPROVED" if resolution == "admin_approved" else "DENIED"
    try:
        client.table("scan_audit_log").insert({
            "org_id": admin.org_id,
            "risk_flag_id": flag_id,
            "message": f"Risk flag {verb} by {admin.employee_id} (tier={flag['tier']}).",
            "actor": admin.employee_id,
            "incident_id": flag_id,
            "risk": flag["tier"],
            "action": f"risk_flag_{verb.lower()}",
            "decision": verb,
            "execution_result": "success",
            "reference_id": flag_id,
        }).execute()
    except Exception:
        # Audit log write failure must NEVER roll back or block the actual
        # approve/deny decision that already succeeded — the risk flag
        # update above is the source of truth for the employee's status.
        pass

    return RiskFlagActionOut(
        id=updated["id"], status=updated["status"], resolution=updated["resolution"],
        approved_by=updated["approved_by"], approved_at=updated["approved_at"],
    )


@router.post("/risk-flags/{flag_id}/approve", response_model=RiskFlagActionOut)
def approve_risk_flag(flag_id: str, admin: AdminUser = Depends(require_admin)):
    return _resolve_flag(flag_id, admin, resolution="admin_approved")


@router.post("/risk-flags/{flag_id}/deny", response_model=RiskFlagActionOut)
def deny_risk_flag(flag_id: str, admin: AdminUser = Depends(require_admin)):
    return _resolve_flag(flag_id, admin, resolution="admin_denied")