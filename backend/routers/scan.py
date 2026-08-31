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

import logging
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from typing import List, Literal, Optional
from pydantic import BaseModel

from models import AdminUser
from routers.org_auth import get_current_admin, require_admin
from services import sca_services
from services.risk_classifier import get_display_severity

logger = logging.getLogger("sentry.scan_router")

router = APIRouter(tags=["scan"])


class ScanResultOut(BaseModel):
    risk_flag_id: str
    employee_id: Optional[str] = None
    source_type: str = "sca_scan"
    app_name: Optional[str] = None
    package_name: str
    package_version: Optional[str] = None
    ecosystem: str
    vuln_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None
    severity_label: str = "Critical"  # Low/Medium/High/Critical — display only
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
    """
    ADMIN ONLY (require_admin) — a non-admin gets a clean 403.

    REWRITTEN per user request: this is now a purely DYNAMIC scan — no
    hardcoded package list. Every call does a real, one-shot read of
    THIS machine's actual Windows notification history (see
    services/notification_capture.py), scores every notification found
    with the same explainable heuristic as notification_poller.py, and
    persists ALL of them (not just ones above a fixed threshold) so the
    admin dashboard can show a genuine Low/Medium/High/Critical
    distribution rather than only ever-escalating findings.

    If run on a non-Windows machine, or if there are no new notifications
    since the last check, this returns an empty list — that is the
    CORRECT, honest result, not a bug. It never fabricates data to make
    the table look populated.

    Fixed-package SCA scanning (pyyaml/django/requests) still exists as
    real, working code in services/sca_service.scan_fixed_payload() and
    remains reachable via POST /scan/upload for a real requirements.txt —
    it has just been removed from THIS button per the explicit request
    to drop the static 3-result output here.
    """
    from services.notification_capture import capture_new_notifications_once
    from services.risk_classifier import classify_confidence, get_display_severity

    try:
        # min_confidence=0.0: capture EVERY notification found, including
        # benign ones — a real distribution needs real Low-severity items
        # too, not just the above-threshold subset.
        captured = capture_new_notifications_once(min_confidence=0.0)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Notification capture engine error: {exc}")

    out: List[ScanResultOut] = []
    for notif in captured:
        classification = classify_confidence(notif["confidence"])
        severity_label = get_display_severity(notif["confidence"])
        reasons_text = "; ".join(notif["reasons"]) if notif["reasons"] else "No specific heuristic reasons recorded."
        summary = (
            f"OS notification from '{notif['app_name']}'"
            + (f" (arrived {notif['arrival_time']})" if notif["arrival_time"] else "")
            + f": {reasons_text} | Text: {notif['text'][:200]}"
        )
        notif_result = sca_services.ScanResult(
            package_name=notif["app_name"], package_version=None,
            ecosystem="windows-notification", vuln_id=None, cvss_score=None,
            summary=summary, tier=classification.tier, reason=classification.reason,
            raw_osv_response={"source": "notification", **notif},
        )
        try:
            risk_flag = sca_services.persist_scan_result(
                notif_result, org_id=admin.org_id, employee_id=admin.employee_id,
                source_type="notification", app_name=notif["app_name"],
                notification_text=notif["text"],
            )
        except Exception as exc:
            logger.warning(f"Could not persist captured notification '{notif['app_name']}': {exc}")
            continue
        out.append(ScanResultOut(
            risk_flag_id=risk_flag["id"],
            employee_id=admin.employee_id,
            source_type="notification",
            app_name=notif["app_name"],
            package_name=notif["app_name"],
            package_version=None,
            ecosystem="windows-notification",
            vuln_id=None,
            cvss_score=None,
            confidence=notif["confidence"],
            severity_label=severity_label,
            summary=summary,
            tier=classification.tier.value,
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
            employee_id=admin.employee_id,
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

        # Recover the original confidence score for notification rows
        # from raw_osv_response (stored at capture time) so the display
        # severity label is consistent between a fresh scan and a
        # historical read of the same row.
        raw = scan.get("raw_osv_response") or {}
        confidence = raw.get("confidence") if isinstance(raw, dict) else None
        if confidence is not None:
            severity_label = get_display_severity(confidence)
        elif scan.get("cvss_score") is not None:
            # SCA rows: map CVSS 0-10 onto the same 4-level label for a
            # consistent visual scale across both evidence types.
            cvss = scan["cvss_score"]
            severity_label = "Low" if cvss <= 3.9 else "Medium" if cvss <= 6.9 else "High" if cvss <= 8.9 else "Critical"
        else:
            severity_label = "Critical"  # fail-safe: unknown -> worst label, never "Low"

        out.append(ScanResultOut(
            risk_flag_id=(flag["id"] if flag else ""),
            employee_id=scan.get("employee_id"),
            source_type=scan.get("source_type", "sca_scan"),
            app_name=scan.get("app_name"),
            package_name=scan["package_name"] or scan.get("app_name") or "unknown",
            package_version=scan["package_version"],
            ecosystem=scan["ecosystem"],
            vuln_id=scan.get("vuln_id"),
            cvss_score=scan.get("cvss_score"),
            confidence=confidence,
            severity_label=severity_label,
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