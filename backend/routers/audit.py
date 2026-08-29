"""
routers/audit.py
-----------------
GET /audit-log — ADMIN ONLY. Real read path for scan_audit_log, which
was previously write-only (every approve/deny/auto-approval writes a
row, but nothing could display it).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from models import AdminUser
from routers.org_auth import require_admin

router = APIRouter(tags=["audit"])


class AuditEntryOut(BaseModel):
    id: str
    message: str
    actor: Optional[str] = None
    created_at: str


@router.get("/audit-log", response_model=List[AuditEntryOut])
def get_audit_log(admin: AdminUser = Depends(require_admin), limit: int = 100):
    from services.supabase_service import _get_client

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    rows = (
        client.table("scan_audit_log")
        .select("id, message, actor, created_at")
        .eq("org_id", admin.org_id)
        .order("created_at", desc=True)
        .limit(min(limit, 500))
        .execute()
    ).data or []

    return [
        AuditEntryOut(id=r["id"], message=r["message"], actor=r.get("actor"), created_at=r["created_at"])
        for r in rows
    ]