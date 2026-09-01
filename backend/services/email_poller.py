"""
services/email_poller.py
-------------------------
Real email ingestion for one org's monitored mailbox.

Runs as its OWN process, separate from `uvicorn main:app`:

    python services/email_poller.py

What it does, every POLL_INTERVAL_SECONDS:
  1. Logs into the mailbox over IMAP (imaplib, stdlib only — no extra
     dependency) using a Gmail address + app password.
  2. Searches for UNSEEN messages in INBOX.
  3. For each new message, extracts sender/subject/links and runs a simple,
     explainable phishing/deepfake-link heuristic (see `score_message`).
  4. If the heuristic fires, POSTs the finding to the EXISTING
     POST /ingest/email endpoint on the FastAPI backend — so it flows
     through the same correlation_engine + playbook_engine as every other
     evidence source. No parallel/duplicate alert logic.
  5. Marks the message \\Seen either way, so it isn't reprocessed.

Auth model: the poller logs in as the org's admin (username/password from
env) to get a JWT, then sends that JWT with every /ingest/email call, so
alerts it creates are correctly scoped to that org (see main.py's
_optional_admin gating on the ingest routes).

Env vars required:
  IMAP_HOST              default: imap.gmail.com
  IMAP_USER              the monitored Gmail address (must match the org's
                          monitored_mailbox from registration)
  IMAP_APP_PASSWORD      a Gmail App Password (NOT the normal account
                          password — requires 2FA enabled on the account;
                          generate at https://myaccount.google.com/apppasswords)
  SENTRY_API_BASE         default: http://localhost:8000
  SENTRY_ADMIN_USERNAME   the pre-created admin's username
  SENTRY_ADMIN_PASSWORD   the pre-created admin's password
  POLL_INTERVAL_SECONDS   default: 30
"""

from __future__ import annotations

import email
import email.utils
import imaplib
import logging
import os
import re
import time
from email.header import decode_header
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [poller] %(message)s")
logger = logging.getLogger("sentry.email_poller")

IMAP_HOST = os.environ.get("IMAP_HOST", "imap.gmail.com")
IMAP_USER = os.environ.get("IMAP_USER", "")
IMAP_APP_PASSWORD = os.environ.get("IMAP_APP_PASSWORD", "")
API_BASE = os.environ.get("SENTRY_API_BASE", "http://localhost:8000")
ADMIN_USERNAME = os.environ.get("SENTRY_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("SENTRY_ADMIN_PASSWORD", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "30"))

# Very small, explainable heuristics — intentionally simple (rule-based,
# like the rest of the correlation engine) rather than a black box.
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
SUSPICIOUS_TLDS = {".zip", ".xyz", ".top", ".click", ".country", ".gq", ".tk"}
URGENCY_WORDS = {"urgent", "immediately", "verify your account", "wire transfer",
                  "password expires", "click here now", "act now", "suspended"}
LOOKALIKE_BRANDS = {"paypal", "microsoft", "google", "apple", "bank", "irs", "amazon"}


def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    out = []
    for text, enc in parts:
        if isinstance(text, bytes):
            out.append(text.decode(enc or "utf-8", errors="replace"))
        else:
            out.append(text)
    return "".join(out)


def _extract_body(msg: email.message.Message) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_payload(decode=True).decode(
                        part.get_content_charset() or "utf-8", errors="replace"
                    )
                except Exception:
                    continue
        return ""
    try:
        return msg.get_payload(decode=True).decode(
            msg.get_content_charset() or "utf-8", errors="replace"
        )
    except Exception:
        return ""


def score_message(sender: str, subject: str, body: str) -> tuple[float, list[str]]:
    """Returns (confidence 0..1, reasons[]). Pure function, easy to unit test."""
    text = f"{subject}\n{body}".lower()
    reasons: list[str] = []
    score = 0.0

    urls = URL_RE.findall(body)
    for url in urls:
        if any(url.lower().endswith(tld) or f"{tld}/" in url.lower() for tld in SUSPICIOUS_TLDS):
            score += 0.35
            reasons.append(f"Link uses a suspicious TLD: {url}")
        # crude lookalike-domain check: brand name appears in URL but not
        # as the actual registered domain of a known provider.
        for brand in LOOKALIKE_BRANDS:
            if brand in url.lower() and brand not in sender.lower():
                score += 0.25
                reasons.append(f"Link references '{brand}' but sender is '{sender}' (possible lookalike).")
                break

    hits = [w for w in URGENCY_WORDS if w in text]
    if hits:
        score += min(0.3, 0.1 * len(hits))
        reasons.append(f"Urgency/pressure language detected: {', '.join(hits)}")

    if urls and not reasons:
        # unscored links still add a small baseline signal worth surfacing
        score += 0.1
        reasons.append(f"Message contains {len(urls)} link(s) with no other signal.")

    return round(min(score, 0.97), 3), reasons


def get_admin_token() -> str:
    # FIX: was calling /admin/login (doesn't exist) — correct endpoint is /login
    # which accepts employee_id + password as form data (see routers/org_auth.py)
    resp = requests.post(
        f"{API_BASE}/login",
        data={"employee_id": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    for key in ("token", "access_token", "accessToken", "jwt"):
        if key in body:
            return body[key]
    raise RuntimeError(f"Could not extract token from /login response: {list(body.keys())}")



def post_ingest_email(token: str, description: str, confidence: float, title_hint: str) -> None:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    resp = requests.post(
        f"{API_BASE}/ingest/email",
        headers={"Authorization": f"Bearer {token}"},
        json={"description": description, "confidence": confidence, "title_hint": title_hint},
        timeout=10,
    )
    if resp.status_code >= 400:
        logger.warning(f"Ingest failed ({resp.status_code}): {resp.text}")
    else:
        try:
            j = resp.json()
            alert_id = j.get('id') or (j.get('alert') and j.get('alert').get('id'))
        except Exception:
            alert_id = None
        logger.info(f"Alert created: {alert_id} — {title_hint}")


def poll_once(imap: imaplib.IMAP4_SSL, token: str) -> None:
    imap.select("INBOX")
    status, data = imap.search(None, "UNSEEN")
    if status != "OK":
        logger.warning(f"IMAP search failed: {status}")
        return

    ids = data[0].split()
    if not ids:
        logger.info("No new mail.")
        return

    # Import domain verifier for sender whitelist checking (org_id needed — derive from token)
    _org_id = None
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        # Decode org_id from token without importing org_auth (avoids circular import)
        import base64, json as _json
        parts = token.split(".")
        if len(parts) == 3:
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            _org_id = _json.loads(base64.urlsafe_b64decode(payload_b64)).get("org_id")
    except Exception:
        pass

    for msg_id in ids:
        status, msg_data = imap.fetch(msg_id, "(RFC822)")
        if status != "OK" or not msg_data or not msg_data[0]:
            continue
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)

        sender = _decode(msg.get("From", ""))
        subject = _decode(msg.get("Subject", ""))
        body = _extract_body(msg)
        date_str = msg.get("Date", "")

        # Parse date to ISO
        date_iso = None
        if date_str:
            try:
                import email.utils as _eu
                date_iso = _eu.parsedate_to_datetime(date_str).isoformat()
            except Exception:
                date_iso = date_str

        confidence, reasons = score_message(sender, subject, body)
        logger.info(f"Scanned '{subject}' from {sender} — score={confidence}")

        # DOMAIN VERIFICATION: boost confidence if sender is not whitelisted
        domain = sender.split("@")[-1].strip(">").strip() if "@" in sender else ""
        domain_trusted = False
        if _org_id:
            try:
                import sys, os as _os
                sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), ".."))
                from services.domain_verifier import verify_email_sender
                verify = verify_email_sender(sender, _org_id)
                domain_trusted = verify.trusted
                if not verify.trusted:
                    confidence = round(min(confidence + 0.2, 0.97), 3)
                    reasons.append(f"Sender domain '{verify.domain}' not in org trusted whitelist (+0.2 boost).")
                    logger.info(f"  Domain '{verify.domain}' untrusted — boosted confidence to {confidence}")
            except Exception as exc:
                logger.warning(f"Domain verification skipped: {exc}")

        # Write to email_cache so /emails/recent can serve this without
        # opening its own IMAP connection (per-request IMAP is unsafe at
        # 3s polling frequency — see Flag 2 in review notes).
        try:
            from services import email_cache
            email_cache.write_emails([{
                "id": msg_id.decode() if isinstance(msg_id, bytes) else str(msg_id),
                "sender": sender,
                "subject": subject,
                "snippet": body[:200] if body else "",
                "date_iso": date_iso,
                "body_preview": body[:500] if body else "",
                "urls": URL_RE.findall(body or "")[:10],
                "confidence": confidence,
                "domain": domain,
                "domain_trusted": domain_trusted,
                "domain_status": "Trusted" if domain_trusted else "Unknown",
                "risk_reasons": reasons,
            }])
        except Exception as exc:
            logger.warning(f"email_cache write failed (non-fatal): {exc}")

        if confidence >= 0.3:
            description = (
                f"Email from '{sender}' subject '{subject}': " + "; ".join(reasons)
            )
            post_ingest_email(
                token,
                description=description,
                confidence=confidence,
                title_hint=f"Suspicious email: {subject[:80]}",
            )

        # Mark seen either way, so we never reprocess it.
        imap.store(msg_id, "+FLAGS", "\\Seen")


def main() -> None:
    missing = [name for name, val in [
        ("IMAP_USER", IMAP_USER), ("IMAP_APP_PASSWORD", IMAP_APP_PASSWORD),
        ("SENTRY_ADMIN_USERNAME", ADMIN_USERNAME), ("SENTRY_ADMIN_PASSWORD", ADMIN_PASSWORD),
    ] if not val]
    if missing:
        logger.error(f"Missing required env vars: {', '.join(missing)}. See module docstring.")
        return

    logger.info(f"Logging into admin API at {API_BASE} as {ADMIN_USERNAME}...")
    token = get_admin_token()
    logger.info("Got admin token. Starting IMAP poll loop...")

    while True:
        try:
            imap = imaplib.IMAP4_SSL(IMAP_HOST)
            imap.login(IMAP_USER, IMAP_APP_PASSWORD)
            try:
                poll_once(imap, token)
            finally:
                imap.logout()
        except imaplib.IMAP4.error as exc:
            logger.error(f"IMAP error: {exc}")
        except requests.RequestException as exc:
            logger.error(f"API request failed ({exc}) — will retry, and refresh token if expired.")
            try:
                token = get_admin_token()
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"Unexpected error in poll loop: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
