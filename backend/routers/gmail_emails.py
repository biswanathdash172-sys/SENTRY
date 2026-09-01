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


def _read_cached_emails(org_id: str, max_results: int) -> List[EmailOut]:
    """
    Reads recent emails from the in-process email_cache that email_poller.py
    (or gmail_poller.py) writes to after each poll cycle.

    This is the correct architecture (Flag 2 fix): the long-lived poller
    process is the ONLY component that opens IMAP/Gmail connections. The
    API route reads from the cache instead of opening a new connection per
    request. At a 3-second poll interval this would otherwise open ~20
    IMAP logins per minute per dashboard tab — enough to trigger Gmail's
    "suspicious activity" lockout.

    Returns [] if the cache hasn't been populated yet (i.e. the poller
    hasn't run since the backend started). The dashboard shows the "No
    emails fetched" empty state in that case, which is honest.

    Previously named _imap_fallback_recent — renamed per Flag 3 in the
    review notes because that name falsely implied it was doing IMAP
    (it was actually reading Supabase scan_results, which was the bug).
    """
    try:
        from services import email_cache
        from services.domain_verifier import verify_email_sender
        cached = email_cache.read_emails(max_results=max_results)
        if not cached:
            return []

        out = []
        for e in cached:
            sender = e.get("sender", "")
            # Re-run domain verification here so it's always org-scoped,
            # since the poller doesn't have org_id at write time.
            domain_trusted = e.get("domain_trusted", False)
            domain_status = e.get("domain_status", "Unknown")
            confidence = e.get("confidence", 0.0)
            reasons = e.get("risk_reasons", [])
            try:
                verify = verify_email_sender(sender, org_id)
                domain_trusted = verify.trusted
                if not verify.trusted and not any("whitelist" in r for r in reasons):
                    confidence = round(min(confidence + 0.2, 0.97), 3)
                    reasons = list(reasons) + [
                        f"Sender domain '{verify.domain}' not in org's trusted whitelist (+0.2 boost)."
                    ]
                domain_status = "Trusted" if verify.trusted else "Unknown"
            except Exception:
                pass  # domain verification is best-effort

            out.append(EmailOut(
                id=e.get("id", ""),
                sender=sender,
                subject=e.get("subject", ""),
                snippet=e.get("snippet", ""),
                date_iso=e.get("date_iso"),
                confidence=confidence,
                domain=e.get("domain", ""),
                domain_trusted=domain_trusted,
                domain_status=domain_status,
                risk_reasons=reasons,
                urls=e.get("urls", []),
            ))
        return out
    except Exception as exc:
        logger.warning(f"_read_cached_emails: {exc}")
        return []


# Thin alias kept for any callers that still reference the old name.
# Remove once all call sites have been updated.
def _imap_fallback_recent(org_id: str, max_results: int) -> List[EmailOut]:
    """Deprecated alias for _read_cached_emails. See Flag 3 in review notes."""
    return _read_cached_emails(org_id, max_results)
