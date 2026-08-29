"""
routers/notification_ingest.py
--------------------------------
Real ingestion path for Windows-notification findings (Item A), unified
into the SAME scan_results/risk_flags pipeline as SCA scans (Option B,
confirmed with the user) — NOT the old separate Alert/STORE system.

DELIBERATELY OPEN TO ANY AUTHENTICATED EMPLOYEE (get_current_admin, NOT
require_admin): this is the actual fix for real employee traceability.
Each employee is meant to run their OWN notification_poller.py instance,
logged in as THEMSELVES — so risk_flags.employee_id ends up being the
real employee whose machine produced the finding, not always the org
admin. An admin's dashboard then sees findings correctly attributed to
whoever's machine they came from.

This reuses sca_service.persist_scan_result() completely unchanged —
building a plain ScanResult object with a notification-appropriate shape
(package_name=app_name, ecosystem="windows-notification", tier from
risk_classifier.classify_confidence() instead of classify_cvss()) means
zero duplicated persistence/auto-approval logic between SCA and
notification findings. One write path, one set of fail-safes.
"""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from models import AdminUser
from routers.org_auth import get_current_admin
from services import sca_services
from services.risk_classifier import classify_confidence

router = APIRouter(tags=["notification-ingest"])


class NotificationIngestRequest(BaseModel):
    app_name: str = Field(..., min_length=1, max_length=300)
    text: str = Field(..., min_length=1, max_length=2000)
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasons: List[str] = Field(default_factory=list)
    arrival_time: Optional[str] = None


class NotificationIngestResponse(BaseModel):
    risk_flag_id: str
    app_name: str
    tier: str
    risk_flag_status: str
    resolution: Optional[str] = None


@router.post("/ingest/notification", response_model=NotificationIngestResponse)
def ingest_notification(
    req: NotificationIngestRequest,
    caller: AdminUser = Depends(get_current_admin),  # ANY employee, not admin-only
):
    """
    Called by notification_poller.py running on an employee's own
    machine, authenticated as that employee. org_id/employee_id are
    ALWAYS taken from the caller's own JWT — never from the request body
    — so one employee's poller can never attribute a finding to a
    different employee.
    """
    classification = classify_confidence(req.confidence)

    reasons_text = "; ".join(req.reasons) if req.reasons else "No specific heuristic reasons recorded."
    summary = (
        f"OS notification from '{req.app_name}'"
        + (f" (arrived {req.arrival_time})" if req.arrival_time else "")
        + f": {reasons_text} | Text: {req.text[:200]}"
    )

    result = sca_services.ScanResult(
        package_name=req.app_name,
        package_version=None,
        ecosystem="windows-notification",
        vuln_id=None,
        cvss_score=None,
        summary=summary,
        tier=classification.tier,
        reason=classification.reason,
        raw_osv_response={
            "source": "notification", "app_name": req.app_name,
            "text": req.text, "confidence": req.confidence,
            "reasons": req.reasons, "arrival_time": req.arrival_time,
        },
    )

    try:
        risk_flag = sca_services.persist_scan_result(
            result, org_id=caller.org_id, employee_id=caller.employee_id,
            source_type="notification", app_name=req.app_name, notification_text=req.text,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Could not save notification finding: {exc}")

    return NotificationIngestResponse(
        risk_flag_id=risk_flag["id"],
        app_name=req.app_name,
        tier=result.tier.value,
        risk_flag_status=risk_flag["status"],
        resolution=risk_flag.get("resolution"),
    )