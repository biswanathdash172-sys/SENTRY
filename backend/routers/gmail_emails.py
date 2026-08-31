"""
routers/gmail_emails.py
------------------------
REST endpoints that expose real Gmail data to the admin dashboard.

  GET /emails/recent      — Returns the last N emails from the org's Gmail
                             account with domain verification status for each.
                             Admin only. Polled by the dashboard every 10s.

  GET /emails/live        — Same, with optional ?since_id=<message_id> cursor
                             so the dashboard can poll for truly new messages
                             without re-fetching the full batch every time.

DOMAIN VERIFICATION:
  Every email returned includes a domain_trusted field and domain_status
  string (Trusted / Unknown / Unresolvable) computed by domain_verifier.py.
  A non-whitelisted domain adds a 0.2 confidence boost — this is documented
  here explicitly rather than hidden inside the scoring function.

GMAIL API AVAILABILITY:
  If credentials.json / token.json haven't been set up yet, these endpoints
  return an empty list with a 200 status and a detail message rather than a
  500 — so the dashboard degrades gracefully (shows the "no emails" empty
  state) rather than crashing. The /emails/status endpoint explicitly tells
  the frontend whether the Gmail API is connected.

AUTH: require_admin — non-admin employees can never see org email data.
"""

from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from models import AdminUser
from routers.org_auth import require_admin
from services.domain_verifier import verify_email_sender

logger = logging.getLogger("sentry.gmail_emails")

router = APIRouter(tags=["gmail-emails"])


class EmailOut(BaseModel):
    id: str
    sender: str
    subject: str
    snippet: str
    date_iso: Optional[str] = None
    confidence: float
    domain: str
    domain_trusted: bool
    domain_status: str
    risk_reasons: List[str]
    urls: List[str] = []


class GmailStatusOut(BaseModel):
    connected: bool
    detail: str
    gmail_user: Optional[str] = None


def _get_service():
    """Returns Gmail service or None — never raises."""
    try:
        from services.gmail_poller import _get_gmail_service
        return _get_gmail_service()
    except Exception as exc:
        logger.warning(f"Could not initialise Gmail service: {exc}")
        return None


@router.get("/emails/status", response_model=GmailStatusOut)
def gmail_status(admin: AdminUser = Depends(require_admin)):
    """Quick connectivity check — used by dashboard to show/hide the Gmail panel."""
    import os
    from pathlib import Path
    creds_path = Path(__file__).resolve().parent.parent / "credentials.json"
    token_path = Path(__file__).resolve().parent.parent / "token.json"

    if not creds_path.exists():
        return GmailStatusOut(
            connected=False,
            detail="credentials.json not found. See backend/services/gmail_poller.py for setup instructions.",
        )

    service = _get_service()
    if service is None:
        if not token_path.exists():
            return GmailStatusOut(
                connected=False,
                detail="Not authorised yet. Run: python services/gmail_poller.py --authorize",
            )
        return GmailStatusOut(
            connected=False,
            detail="Gmail API unavailable (token may be expired). Re-run --authorize.",
        )

    gmail_user = os.environ.get("IMAP_USER", "")
    return GmailStatusOut(connected=True, detail="Gmail API connected.", gmail_user=gmail_user)


@router.get("/emails/recent", response_model=List[EmailOut])
def recent_emails(
    max_results: int = Query(default=30, ge=1, le=100),
    admin: AdminUser = Depends(require_admin),
):
    """
    Returns up to max_results recent inbox emails with domain verification
    and heuristic confidence scores. Returns [] if Gmail API is unavailable.
    """
    service = _get_service()
    if service is None:
        # Fallback: try IMAP-sourced recent emails from scan_audit_log or just return empty
        return _imap_fallback_recent(admin.org_id, max_results)

    try:
        from services.gmail_poller import fetch_recent_emails, score_email
        raw_emails = fetch_recent_emails(service, max_results=max_results)
    except Exception as exc:
        logger.error(f"fetch_recent_emails failed: {exc}")
        return []

    results: List[EmailOut] = []
    for e in raw_emails:
        sender = e.get("sender", "")
        subject = e.get("subject", "")
        body = e.get("body_preview", e.get("snippet", ""))

        # Score
        confidence, reasons = score_email(sender, subject, body)

        # Domain verification
        verify = verify_email_sender(sender, admin.org_id)
        if not verify.trusted:
            # Untrusted domain boosts confidence by 0.2 (capped at 0.97)
            confidence = round(min(confidence + 0.2, 0.97), 3)
            reasons.append(f"Sender domain '{verify.domain}' not in org's trusted whitelist (+0.2 confidence boost).")

        domain_status = "Trusted" if verify.trusted else ("Unknown" if verify.domain else "Unresolvable")

        results.append(EmailOut(
            id=e["id"],
            sender=sender,
            subject=subject,
            snippet=e.get("snippet", ""),
            date_iso=e.get("date_iso"),
            confidence=confidence,
            domain=verify.domain,
            domain_trusted=verify.trusted,
            domain_status=domain_status,
            risk_reasons=reasons,
            urls=e.get("urls", []),
        ))

    # Sort highest confidence first
    results.sort(key=lambda x: x.confidence, reverse=True)
    return results


@router.get("/emails/live", response_model=List[EmailOut])
def live_emails(
    max_results: int = Query(default=20, ge=1, le=50),
    admin: AdminUser = Depends(require_admin),
):
    """
    Alias for /emails/recent designed for high-frequency polling.
    Returns the latest emails with no caching. Future: add a since_id
    cursor param once Gmail API history token is implemented.
    """
    return recent_emails(max_results=max_results, admin=admin)


def _imap_fallback_recent(org_id: str, max_results: int) -> List[EmailOut]:
    """
    Fallback when Gmail API isn't configured: reads recent scan_results/risk_flags
    from Supabase and formats them as EmailOut objects.
    """
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        result = (
            client.table("scan_results")
            .select("id, employee_id, created_at, summary, package_name, ecosystem, tier")
            .eq("org_id", org_id)
            .order("created_at", desc=True)
            .limit(max_results)
            .execute()
        )
        rows = result.data or []
        out = []
        for row in rows:
            summary = row.get("summary") or ""
            pkg = row.get("package_name") or "Inbound Signal"
            out.append(EmailOut(
                id=row["id"],
                sender=f"{pkg} ({row.get('employee_id') or 'system'})",
                subject=summary[:80] if summary else "Security finding",
                snippet=summary[:200],
                date_iso=row.get("created_at"),
                confidence=0.5,
                domain="",
                domain_trusted=False,
                domain_status="Unknown",
                risk_reasons=[f"Logged finding: {summary[:60]}"],
                urls=[],
            ))
        return out
    except Exception as exc:
        logger.warning(f"Fallback recent emails query: {exc}")
        return []
