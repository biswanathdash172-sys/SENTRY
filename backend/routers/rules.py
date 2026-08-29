"""
routers/rules.py
-----------------
Lets the org admin VIEW and UPDATE auto_approval_rules at runtime (Q2/Q6
requirement: "let the org define them at runtime"). This is the missing
write-path that risk_classifier.can_auto_approve() reads from.

  GET /rules   - ADMIN ONLY. Current can_auto_approve setting per tier.
  PUT /rules   - ADMIN ONLY. Update can_auto_approve for ONE tier.

NON-NEGOTIABLE, ENFORCED HERE TOO (third independent layer, on top of
risk_classifier.can_auto_approve()'s hardcoded check and the database's
CHECK constraint in sca_schema.sql): PUT /rules REJECTS any attempt to
set tier="high_risky" with can_auto_approve=true, with a clear 400 before
ever reaching Supabase. Three layers means an attacker (or a bug) would
need to defeat the API validation, the application logic, AND a database
constraint simultaneously to ever auto-approve a high-risk finding.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from typing import List, Literal
from pydantic import BaseModel

from models import AdminUser
from routers.org_auth import require_admin
from services.risk_classifier import RiskTier, ensure_default_rules

router = APIRouter(tags=["rules"])


class RuleOut(BaseModel):
    tier: Literal["not_risky", "part_risky", "high_risky"]
    can_auto_approve: bool


class UpdateRuleRequest(BaseModel):
    tier: Literal["not_risky", "part_risky", "high_risky"]
    can_auto_approve: bool


@router.get("/rules", response_model=List[RuleOut])
def get_rules(admin: AdminUser = Depends(require_admin)):
    """
    Returns the calling org's current auto-approval rule for every tier.
    Calls ensure_default_rules() first (idempotent) so a brand-new org
    that hasn't logged in via /access/verify-org in this process yet
    still gets a complete, correct 3-row response instead of gaps.
    """
    from services.supabase_service import _get_client

    ensure_default_rules(admin.org_id)  # idempotent, never raises

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    rows = (
        client.table("auto_approval_rules")
        .select("tier,can_auto_approve")
        .eq("org_id", admin.org_id)
        .execute()
    ).data or []

    # Guarantee all three tiers are always present in the response, in a
    # stable order, even if a row is somehow missing — fail toward showing
    # "manual" (False) for anything not found, never omitting a tier
    # silently (an admin UI toggle needs to see every tier to be safe).
    by_tier = {r["tier"]: bool(r["can_auto_approve"]) for r in rows}
    return [
        RuleOut(tier=tier.value, can_auto_approve=by_tier.get(tier.value, False))
        for tier in RiskTier
    ]


@router.put("/rules", response_model=RuleOut)
def update_rule(req: UpdateRuleRequest, admin: AdminUser = Depends(require_admin)):
    """
    Updates ONE tier's can_auto_approve flag for the calling org. See
    module docstring — high_risky + true is rejected here with a plain
    400, before Supabase is ever touched, as the first of three
    independent layers protecting this invariant.
    """
    if req.tier == "high_risky" and req.can_auto_approve:
        raise HTTPException(
            status_code=400,
            detail="High-risk findings can never be set to auto-approve. "
                   "This is a non-negotiable safety rule, not a configurable option.",
        )

    from services.supabase_service import _get_client

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    try:
        result = (
            client.table("auto_approval_rules")
            .upsert(
                {
                    "org_id": admin.org_id,
                    "tier": req.tier,
                    "can_auto_approve": req.can_auto_approve,
                    "updated_by": admin.employee_id,
                },
                on_conflict="org_id,tier",
            )
            .execute()
        )
    except Exception as exc:
        # Covers the DATABASE-level CHECK constraint firing as a second,
        # independent rejection if this code path were ever reached with
        # a bad value some other way — surfaced as a real 400, not a 500,
        # since it's an expected validation failure, not a server bug.
        raise HTTPException(status_code=400, detail=f"Could not update rule: {exc}")

    row = result.data[0] if result.data else {"tier": req.tier, "can_auto_approve": req.can_auto_approve}
    return RuleOut(tier=row["tier"], can_auto_approve=bool(row["can_auto_approve"]))