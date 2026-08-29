"""
routers/scan.py
----------------
API surface for the SCA scanning engine.

  POST /scan/demo         - ADMIN ONLY. Runs the fixed test payload
                             against the real OSV.dev API, persists real
                             rows, returns full result detail.
  GET  /scan/results       - ADMIN ONLY. Full scan history for the org.
  GET  /risk-flags/my      - ANY logged-in employee. Their own risk
                             flags, status only — no package/CVSS detail.

RBAC (Option A, now implemented): admin-only routes use require_admin
(routers/org_auth.py), which checks the is_admin claim embedded in the
JWT at login time, sourced from Supabase's employees.is_admin column.
/risk-flags/my deliberately still uses the weaker get_current_admin (any
authenticated employee), since every employee — admin or not — is
entitled to see their own flag statuses.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import List, Literal, Optional
from pydantic import BaseModel

from models import AdminUser
from routers.org_auth import get_current_admin, require_admin
from services import sca_services

router = APIRouter(tags=["scan"])


class ScanResultOut(BaseModel):
    risk_flag_id: str
    source_type: str = "sca_scan"
    app_name: Optional[str] = None
    package_name: str
    package_version: Optional[str] = None
    ecosystem: str
    vuln_id: Optional[str] = None
    cvss_score: Optional[float] = None
    summary: Optional[str] = None
    tier: Literal["not_risky", "part_risky", "high_risky"]
    risk_flag_status: Literal["pending", "completed"]
    resolution: Optional[str] = None


class MyRiskFlagOut(BaseModel):
    id: str
    status: Literal["pending", "completed"]
    created_at: str


@router.post("/scan/demo", response_model=List[ScanResultOut])
def run_demo_scan(admin: AdminUser = Depends(require_admin)):
    """ADMIN ONLY (require_admin) — a non-admin gets a clean 403."""
    try:
        results = sca_services.scan_fixed_payload()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan engine error: {exc}")

    out: List[ScanResultOut] = []
    for result in results:
        try:
            risk_flag = sca_services.persist_scan_result(
                result, org_id=admin.org_id, employee_id=admin.employee_id
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Scanned {result.package_name}=={result.package_version} "
                       f"successfully but could not save the result: {exc}",
            )
        out.append(ScanResultOut(
            risk_flag_id=risk_flag["id"],
            source_type="sca_scan",
            app_name=None,
            package_name=result.package_name,
            package_version=result.package_version,
            ecosystem=result.ecosystem,
            vuln_id=result.vuln_id,
            cvss_score=result.cvss_score,
            summary=result.summary,
            tier=result.tier.value,
            risk_flag_status=risk_flag["status"],
            resolution=risk_flag.get("resolution"),
        ))
    return out


@router.post("/scan/upload", response_model=List[ScanResultOut])
async def upload_and_scan(
    file: UploadFile = File(...),
    admin: AdminUser = Depends(require_admin),
):
    """
    ADMIN ONLY. Real arbitrary-file scanning (Item B): the org uploads a
    real requirements.txt; every exactly-pinned package in it is scanned
    live against OSV.dev, and every unpinned/unresolvable line is recorded
    as an explicit high_risky finding (never silently ignored) — see
    sca_service.scan_requirements_content()'s docstring.
    """
    raw_bytes = await file.read()
    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=400,
            detail="Could not decode the uploaded file as UTF-8 text. "
                   "Please upload a plain-text requirements.txt.",
        )

    try:
        pinned_results, skipped_results = sca_services.scan_requirements_content(content)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Scan engine error: {exc}")

    all_results = pinned_results + skipped_results
    if not all_results:
        raise HTTPException(
            status_code=400,
            detail="No parseable dependency lines found in the uploaded file.",
        )

    out: List[ScanResultOut] = []
    for result in all_results:
        try:
            risk_flag = sca_services.persist_scan_result(
                result, org_id=admin.org_id, employee_id=admin.employee_id
            )
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail=f"Scanned {result.package_name} successfully but could "
                       f"not save the result: {exc}",
            )
        out.append(ScanResultOut(
            risk_flag_id=risk_flag["id"],
            source_type="sca_scan",
            app_name=None,
            package_name=result.package_name,
            package_version=result.package_version,
            ecosystem=result.ecosystem,
            vuln_id=result.vuln_id,
            cvss_score=result.cvss_score,
            summary=result.summary,
            tier=result.tier.value,
            risk_flag_status=risk_flag["status"],
            resolution=risk_flag.get("resolution"),
        ))
    return out


@router.get("/scan/results", response_model=List[ScanResultOut])
def list_scan_results(admin: AdminUser = Depends(require_admin)):
    """ADMIN ONLY (require_admin) — full org-wide scan history."""
    from services.supabase_service import _get_client

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    scans = (
        client.table("scan_results")
        .select("*")
        .eq("org_id", admin.org_id)
        .order("created_at", desc=True)
        .execute()
    ).data or []

    flags = (
        client.table("risk_flags")
        .select("id,scan_result_id,status,resolution")
        .eq("org_id", admin.org_id)
        .execute()
    ).data or []
    flags_by_scan = {f["scan_result_id"]: f for f in flags}

    out: List[ScanResultOut] = []
    for scan in scans:
        flag = flags_by_scan.get(scan["id"])
        out.append(ScanResultOut(
            risk_flag_id=(flag["id"] if flag else ""),
            source_type=scan.get("source_type", "sca_scan"),
            app_name=scan.get("app_name"),
            package_name=scan["package_name"] or scan.get("app_name") or "unknown",
            package_version=scan["package_version"],
            ecosystem=scan["ecosystem"],
            vuln_id=scan.get("vuln_id"),
            cvss_score=scan.get("cvss_score"),
            summary=scan.get("summary"),
            tier=scan["tier"],
            risk_flag_status=(flag["status"] if flag else "pending"),
            resolution=(flag.get("resolution") if flag else None),
        ))
    return out


@router.get("/risk-flags/my", response_model=List[MyRiskFlagOut])
def list_my_risk_flags(admin: AdminUser = Depends(get_current_admin)):
    """
    ANY logged-in employee (admin or not) — deliberately uses
    get_current_admin, not require_admin, since every employee is
    entitled to see their own flags. Query filters by employee_id AND the
    response shape (MyRiskFlagOut) has no package/CVSS/summary fields to
    leak, so this stays safe even if the query filter were ever removed
    by mistake — two independent layers, same pattern as
    auto_approval_rules' CHECK constraint.
    """
    from services.supabase_service import _get_client

    try:
        client = _get_client()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Supabase not available: {exc}")

    flags = (
        client.table("risk_flags")
        .select("id,status,created_at")
        .eq("org_id", admin.org_id)
        .eq("employee_id", admin.employee_id)
        .order("created_at", desc=True)
        .execute()
    ).data or []

    return [
        MyRiskFlagOut(id=f["id"], status=f["status"], created_at=f["created_at"])
        for f in flags
    ]