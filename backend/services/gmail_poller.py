"""
services/gmail_poller.py
-------------------------
Gmail API-based email poller replacing the IMAP approach.

Uses OAuth2 with installed-app credentials (Option B):
  - credentials.json  — downloaded from Google Cloud Console
    (OAuth 2.0 Client ID for "Desktop app")
  - token.json        — auto-created/refreshed after first authorisation
    (stored next to this file)

On first run, this opens a browser tab to authenticate. Subsequent runs
use the cached refresh token in token.json — no user interaction needed.

HOW TO SET UP (one-time):
  1. Go to https://console.cloud.google.com/
  2. Create a project, enable "Gmail API"
  3. Create OAuth2 credentials (type: Desktop app), download as
     backend/credentials.json
  4. Run: python services/gmail_poller.py --authorize
     This opens the browser and writes backend/token.json
  5. The poller then runs with: python services/gmail_poller.py

IMAP FALLBACK:
  If credentials.json doesn't exist, this module falls back to reading
  the IMAP_APP_PASSWORD from .env and using the original imaplib approach
  — so the system degrades gracefully if Gmail API isn't configured yet.

Env vars (same as email_poller.py — no new vars needed unless using a
different account):
  IMAP_USER                     — the Gmail address to monitor
  SENTRY_API_BASE               — backend API base URL
  SENTRY_EMPLOYEE_USERNAME / SENTRY_EMPLOYEE_PASSWORD  — for JWT token
  GMAIL_POLL_INTERVAL_SECONDS  — default 30
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [gmail-poller] %(message)s")
logger = logging.getLogger("sentry.gmail_poller")

API_BASE = os.environ.get("SENTRY_API_BASE", "http://localhost:8000")
ADMIN_USERNAME = os.environ.get("SENTRY_EMPLOYEE_USERNAME", "") or os.environ.get("SENTRY_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("SENTRY_EMPLOYEE_PASSWORD", "") or os.environ.get("SENTRY_ADMIN_PASSWORD", "")
GMAIL_USER = os.environ.get("IMAP_USER", "")
POLL_INTERVAL = int(os.environ.get("GMAIL_POLL_INTERVAL_SECONDS", "30"))

_HERE = Path(__file__).resolve().parent
CREDENTIALS_FILE = _HERE.parent / "credentials.json"
TOKEN_FILE = _HERE.parent / "token.json"

GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

# Reuse same heuristics as email_poller.py for consistency
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".country", ".gq", ".tk"}
URGENCY_WORDS = {
    "urgent", "immediately", "verify your account", "wire transfer",
    "password expires", "click here now", "act now", "suspended",
}
LOOKALIKE_BRANDS = {"paypal", "microsoft", "google", "apple", "bank", "irs", "amazon"}


# ---------------------------------------------------------------------------
# Gmail API credential management
# ---------------------------------------------------------------------------

def _get_gmail_service():
    """
    Returns an authenticated Gmail API service object.
    Handles credential loading + refresh. Returns None if credentials.json
    doesn't exist (fallback to IMAP path in callers).
    """
    if not CREDENTIALS_FILE.exists():
        logger.warning(
            f"credentials.json not found at '{CREDENTIALS_FILE}'. "
            "Gmail API unavailable — use IMAP fallback or run --authorize first."
        )
        return None

    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError:
        logger.error(
            "Google API libraries not installed. Run: "
            "pip install google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client"
        )
        return None

    creds = None
    if TOKEN_FILE.exists():
        creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), GMAIL_SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                TOKEN_FILE.write_text(creds.to_json())
            except Exception as exc:
                logger.error(f"Token refresh failed: {exc}. Re-run --authorize.")
                return None
        else:
            logger.error(
                "No valid token. Run: python services/gmail_poller.py --authorize"
            )
            return None

    return build("gmail", "v1", credentials=creds)


def authorize():
    """One-time OAuth2 authorisation — opens browser, writes token.json."""
    from google_auth_oauthlib.flow import InstalledAppFlow
    flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), GMAIL_SCOPES)
    creds = flow.run_local_server(port=0)
    TOKEN_FILE.write_text(creds.to_json())
    print(f"Authorisation complete. Token saved to: {TOKEN_FILE}")


# ---------------------------------------------------------------------------
# Gmail API message helpers
# ---------------------------------------------------------------------------

def _decode_header_value(value: Optional[str]) -> str:
    if not value:
        return ""
    return value.strip()


def _extract_body_from_part(part: dict) -> str:
    """Recursively extracts plain-text body from a Gmail message part."""
    mime_type = part.get("mimeType", "")
    if mime_type == "text/plain":
        data = part.get("body", {}).get("data", "")
        if data:
            import base64
            try:
                return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
            except Exception:
                return ""
    elif mime_type.startswith("multipart/"):
        for sub in part.get("parts", []):
            text = _extract_body_from_part(sub)
            if text:
                return text
    return ""


def fetch_recent_emails(service, max_results: int = 50) -> list[dict]:
    """
    Fetches the most recent emails from Gmail (all mail, not just unread).
    Returns a list of structured dicts: {id, sender, subject, snippet,
    date_iso, body_preview, urls}.
    Never raises — returns [] on any API error.
    """
    try:
        result = service.users().messages().list(
            userId="me",
            maxResults=max_results,
            labelIds=["INBOX"],
        ).execute()

        messages = result.get("messages", [])
        emails = []
        for msg_meta in messages:
            try:
                msg = service.users().messages().get(
                    userId="me",
                    id=msg_meta["id"],
                    format="full",
                ).execute()

                headers = {h["name"]: h["value"] for h in msg.get("payload", {}).get("headers", [])}
                sender = _decode_header_value(headers.get("From", ""))
                subject = _decode_header_value(headers.get("Subject", "(no subject)"))
                date_str = _decode_header_value(headers.get("Date", ""))
                snippet = msg.get("snippet", "")
                body = _extract_body_from_part(msg.get("payload", {}))

                # Parse date to ISO
                date_iso = None
                if date_str:
                    try:
                        from email.utils import parsedate_to_datetime
                        date_iso = parsedate_to_datetime(date_str).isoformat()
                    except Exception:
                        date_iso = date_str

                urls = URL_RE.findall(body or snippet)

                emails.append({
                    "id": msg_meta["id"],
                    "sender": sender,
                    "subject": subject,
                    "snippet": snippet[:200],
                    "date_iso": date_iso,
                    "body_preview": (body or snippet)[:500],
                    "urls": urls[:10],
                    "thread_id": msg.get("threadId"),
                })
            except Exception as exc:
                logger.warning(f"Skipping message {msg_meta.get('id')}: {exc}")
                continue

        return emails
    except Exception as exc:
        logger.error(f"Gmail API list failed: {exc}")
        return []


def score_email(sender: str, subject: str, body: str) -> tuple[float, list[str]]:
    """Same heuristic scoring as email_poller.py — kept in sync."""
    text = f"{subject}\n{body}".lower()
    reasons: list[str] = []
    score = 0.0

    urls = URL_RE.findall(body)
    for url in urls:
        if any(url.lower().endswith(tld) or f"{tld}/" in url.lower() for tld in SUSPICIOUS_TLDS):
            score += 0.35
            reasons.append(f"Link uses a suspicious TLD: {url[:80]}")
        for brand in LOOKALIKE_BRANDS:
            if brand in url.lower() and brand not in sender.lower():
                score += 0.25
                reasons.append(f"Link references '{brand}' but sender is '{sender[:60]}' (possible lookalike).")
                break

    hits = [w for w in URGENCY_WORDS if w in text]
    if hits:
        score += min(0.3, 0.1 * len(hits))
        reasons.append(f"Urgency/pressure language: {', '.join(hits)}")

    if urls and not reasons:
        score += 0.1
        reasons.append(f"Message contains {len(urls)} link(s) with no other signal.")

    return round(min(score, 0.97), 3), reasons


# ---------------------------------------------------------------------------
# Token + API call helpers
# ---------------------------------------------------------------------------

def get_sentry_token() -> str:
    resp = requests.post(
        f"{API_BASE}/login",
        data={"employee_id": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    if "token" not in body:
        raise RuntimeError(f"Login response had no 'token': {body}")
    return body["token"]


def post_ingest_email(token: str, description: str, confidence: float, title_hint: str) -> None:
    resp = requests.post(
        f"{API_BASE}/ingest/email",
        headers={"Authorization": f"Bearer {token}"},
        json={"description": description, "confidence": confidence, "title_hint": title_hint},
        timeout=10,
    )
    if resp.status_code >= 400:
        logger.warning(f"Ingest failed ({resp.status_code}): {resp.text}")
    else:
        logger.info(f"Alert created — {title_hint}")


# ---------------------------------------------------------------------------
# Main poll loop
# ---------------------------------------------------------------------------

def poll_once(service, token: str) -> None:
    emails = fetch_recent_emails(service, max_results=20)
    if not emails:
        logger.info("No emails fetched (or API unavailable).")
        return

    for email_data in emails:
        sender = email_data["sender"]
        subject = email_data["subject"]
        body = email_data["body_preview"]

        confidence, reasons = score_email(sender, subject, body)
        logger.info(f"Scanned '{subject}' from {sender[:60]} — score={confidence}")

        domain = sender.split("@")[-1].strip(">").strip() if "@" in sender else ""

        # Write to email_cache so /emails/recent can serve this without
        # opening its own Gmail API connection per request (Flag 2 fix).
        try:
            from services import email_cache
            email_cache.write_emails([{
                "id": email_data["id"],
                "sender": sender,
                "subject": subject,
                "snippet": email_data.get("snippet", ""),
                "date_iso": email_data.get("date_iso"),
                "body_preview": body[:500],
                "urls": email_data.get("urls", []),
                "confidence": confidence,
                "domain": domain,
                "domain_trusted": False,   # domain_verifier is not available here without org_id
                "domain_status": "Unknown",
                "risk_reasons": reasons,
            }])
        except Exception as exc:
            logger.warning(f"email_cache write failed (non-fatal): {exc}")

        if confidence >= 0.3:
            description = f"Email from '{sender}' subject '{subject}': " + "; ".join(reasons)
            post_ingest_email(
                token,
                description=description,
                confidence=confidence,
                title_hint=f"Suspicious email: {subject[:80]}",
            )



def main() -> None:
    import sys
    if "--authorize" in sys.argv:
        authorize()
        return

    missing = [name for name, val in [
        ("SENTRY_EMPLOYEE_USERNAME", ADMIN_USERNAME),
        ("SENTRY_EMPLOYEE_PASSWORD", ADMIN_PASSWORD),
    ] if not val]
    if missing:
        logger.error(f"Missing env vars: {', '.join(missing)}")
        return

    service = _get_gmail_service()
    if service is None:
        logger.error("Gmail API not available. See module docstring for setup instructions.")
        return

    logger.info(f"Gmail API connected. Logging into Sentry as {ADMIN_USERNAME}...")
    token = get_sentry_token()
    logger.info("Got token. Starting Gmail poll loop...")

    while True:
        try:
            poll_once(service, token)
        except requests.RequestException as exc:
            logger.error(f"API request failed ({exc}) — refreshing token.")
            try:
                token = get_sentry_token()
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"Unexpected error: {exc}")
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
