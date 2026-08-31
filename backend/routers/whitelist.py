"""
routers/whitelist.py
----------------------
Domain whitelist management endpoints (admin-only) with hybrid Supabase + local persistence.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from models import AdminUser
from routers.org_auth import require_admin
from services.domain_verifier import _load_local_whitelist, _save_local_whitelist, get_trusted_domains

logger = logging.getLogger("sentry.whitelist")

router = APIRouter(prefix="/whitelist", tags=["whitelist"])

_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]{3,253}$")


class DomainItem(BaseModel):
    domain: str
    added_by: Optional[str] = None
    added_at: Optional[str] = None


class AddDomainRequest(BaseModel):
    domain: str


def _normalise(domain: str) -> str:
    return domain.strip().lower().rstrip(".").lstrip("@")


def _validate_domain(domain: str) -> str:
    d = _normalise(domain)
    if not d or not _DOMAIN_RE.match(d) or "." not in d:
        raise HTTPException(
            status_code=422,
            detail=f"'{domain}' is not a valid domain name (e.g. 'example.com').",
        )
    return d


@router.get("/domains", response_model=List[DomainItem])
def list_trusted_domains(admin: AdminUser = Depends(require_admin)):
    """Returns all trusted domains for the calling admin's org."""
    # 1. Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        result = (
            client.table("domain_whitelist")
            .select("domain, added_by, added_at")
            .eq("org_id", admin.org_id)
            .order("added_at", desc=True)
            .execute()
        )
        if result.data is not None:
            return [
                DomainItem(
                    domain=row["domain"],
                    added_by=row.get("added_by"),
                    added_at=row.get("added_at"),
                )
                for row in result.data
            ]
    except Exception:
        pass

    # 2. Fallback to local store
    wl = _load_local_whitelist()
    doms = wl.get(admin.org_id, [])
    return [DomainItem(domain=d, added_by="admin", added_at=None) for d in doms]


@router.post("/domains", response_model=DomainItem, status_code=201)
def add_trusted_domain(
    req: AddDomainRequest,
    admin: AdminUser = Depends(require_admin),
):
    domain = _validate_domain(req.domain)
    now = datetime.now(timezone.utc).isoformat()

    # 1. Save to local store
    wl = _load_local_whitelist()
    if admin.org_id not in wl:
        wl[admin.org_id] = []
    if domain not in wl[admin.org_id]:
        wl[admin.org_id].append(domain)
        _save_local_whitelist()

    # 2. Try Supabase (best-effort)
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        client.table("domain_whitelist").insert({
            "org_id": admin.org_id,
            "domain": domain,
            "added_by": admin.employee_id,
            "added_at": now,
        }).execute()
    except Exception:
        pass

    return DomainItem(domain=domain, added_by=admin.employee_id, added_at=now)


@router.delete("/domains/{domain}", status_code=204)
def remove_trusted_domain(domain: str, admin: AdminUser = Depends(require_admin)):
    domain = _validate_domain(domain)

    # 1. Remove from local store
    wl = _load_local_whitelist()
    if admin.org_id in wl and domain in wl[admin.org_id]:
        wl[admin.org_id].remove(domain)
        _save_local_whitelist()

    # 2. Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        client.table("domain_whitelist").delete() \
            .eq("org_id", admin.org_id) \
            .eq("domain", domain) \
            .execute()
    except Exception:
        pass

    return None
