"""
services/notification_poller.py
---------------------------------
Real Windows OS-notification capture (Item A). Runs as its OWN local
process on the employee's/admin's Windows machine — mirrors
email_poller.py's pattern exactly (separate script, own auth token,
pushes findings into the SAME correlation/playbook pipeline via an
existing /ingest/* route).

    python services/notification_poller.py

HONESTY NOTE — READ BEFORE RELYING ON THIS IN A DEMO (confirmed with the
user at Q5): Windows does not expose a supported public API for reading
notification HISTORY. This module reads the undocumented SQLite database
at:

    %LOCALAPPDATA%\\Microsoft\\Windows\\Notifications\\wpndatabase.db

SCHEMA STATUS: the exact column layout below was CONFIRMED against a
real Windows 11 machine's live wpndatabase.db on 2026-08-24 (via
PRAGMA table_info()) — Notification(Order, Id, HandlerId, ActivityId,
Type, Payload, Tag, Group, ExpiryTime, ArrivalTime, DataVersion,
PayloadType, BootId, ExpiresOnReboot) and NotificationHandler(RecordId,
PrimaryId, WNSId, HandlerType, WNFEventName, SystemDataPropertySet,
CreatedTime, ModifiedTime, ParentId, ContainerSid) — joined via
Notification.HandlerId = NotificationHandler.RecordId. This is still an
unofficial, undocumented format: it worked on the machine it was
verified against, but Microsoft has not published or guaranteed this
schema, and it may differ on other Windows versions/builds/updates. The
code below fails gracefully (clear RuntimeError, no crash, no fabricated
data) if a future Windows update changes it again.

WHY COPY-THEN-READ: Windows' Notification Platform service holds this
file open continuously, so a direct sqlite3.connect() often fails with
"database is locked". We copy the file to a temp path first (a point-in-
time snapshot) and read from the copy — the standard, safe workaround.

WHAT COUNTS AS "REAL DATA" HERE: every notification title/body/app name
this module reports is extracted directly from your live Windows
notification database at run time — nothing is a fixture or placeholder.
The HEURISTIC SCORING (which notifications look suspicious) is
deliberately simple and rule-based, the same "explainable over opaque"
choice as email_poller.py's score_message() and rules_engine.py.

FLOW:
  1. Copy wpndatabase.db to a temp file (dodges the file lock).
  2. Query the Notification + NotificationHandler tables for rows newer
     than the last-seen Id (tracked in a small local state file).
  3. Extract plain text from each notification's Payload blob (toast
     XML, usually UTF-16LE encoded).
  4. Score each notification with simple, explainable heuristics.
  5. POST anything scoring above threshold to the EXISTING
     POST /ingest/endpoint route (source_type="endpoint" — an OS
     notification is fundamentally an endpoint-originated signal), using
     an admin JWT, exactly like email_poller.py's post_ingest_email().
  6. Track the highest Id seen so re-runs never reprocess old notifications.

Env vars required (same names/pattern as backend/.env.example):
  SENTRY_API_BASE              default: http://localhost:8000
  SENTRY_EMPLOYEE_USERNAME  -> the EMPLOYEE_ID this machine's user logs in
                               as. Does NOT need to be an admin account —
                               each employee should run this poller logged
                               in as THEMSELVES, so risk_flags.employee_id
                               correctly traces back to the real affected
                               employee (see routers/notification_ingest.py).
  SENTRY_EMPLOYEE_PASSWORD  -> that employee's password
  NOTIFICATION_POLL_INTERVAL_SECONDS   default: 30
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sqlite3
import struct
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [notif-poller] %(message)s")
logger = logging.getLogger("sentry.notification_poller")

API_BASE = os.environ.get("SENTRY_API_BASE", "http://localhost:8000")
ADMIN_USERNAME = os.environ.get("SENTRY_EMPLOYEE_USERNAME", "") or os.environ.get("SENTRY_ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.environ.get("SENTRY_EMPLOYEE_PASSWORD", "") or os.environ.get("SENTRY_ADMIN_PASSWORD", "")
POLL_INTERVAL_SECONDS = int(os.environ.get("NOTIFICATION_POLL_INTERVAL_SECONDS", "30"))

STATE_FILE = Path(__file__).resolve().parent / ".notification_poller_state.json"

# Windows FILETIME epoch (1601-01-01) offset from Unix epoch, in 100-ns ticks.
_FILETIME_EPOCH_OFFSET = 116444736000000000


def _wpndb_path() -> Path:
    local_appdata = os.environ.get("LOCALAPPDATA", "")
    if not local_appdata:
        raise RuntimeError(
            "LOCALAPPDATA environment variable not set — this script must "
            "run on Windows, as a normal (non-elevated) user."
        )
    return Path(local_appdata) / "Microsoft" / "Windows" / "Notifications" / "wpndatabase.db"


def _filetime_to_datetime(filetime: Optional[int]) -> Optional[datetime]:
    """Converts a Windows FILETIME integer to a UTC datetime. Returns None
    (never raises, never fabricates a fake time) if the value is missing
    or clearly invalid — a malformed timestamp is reported as unknown,
    not silently defaulted to 'now'."""
    if not filetime or filetime <= 0:
        return None
    try:
        unix_ticks = filetime - _FILETIME_EPOCH_OFFSET
        if unix_ticks < 0:
            return None
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=unix_ticks / 10)
    except (OverflowError, ValueError):
        return None


def _snapshot_database() -> Path:
    """
    Copies the live, locked wpndatabase.db to a temp file so we can read
    it without fighting the Windows Notification Platform service for the
    file lock. Raises a clear error if even the COPY fails (e.g. the file
    genuinely doesn't exist on this machine) — that's a real failure the
    caller needs to know about, not something to fail-safe silently past.
    """
    source = _wpndb_path()
    if not source.exists():
        raise FileNotFoundError(
            f"Windows notification database not found at '{source}'. "
            f"This is expected on non-Windows systems, or if no "
            f"notifications have ever been shown on this machine."
        )

    tmp_dir = Path(tempfile.gettempdir())
    tmp_path = tmp_dir / f"sentry_wpndb_snapshot_{int(time.time())}.db"
    shutil.copy2(source, tmp_path)
    return tmp_path


def _extract_text_from_payload(payload: bytes) -> str:
    """
    Best-effort plain-text extraction from a notification's raw Payload
    blob. The payload is typically the toast notification's XML,
    UTF-16LE encoded, sometimes with binary framing bytes around it.

    STRATEGY (deliberately layered, cheapest/most-reliable first):
      1. Try decoding the whole blob as UTF-16LE, then strip XML tags —
         this is correct for the common case.
      2. If that yields nothing readable, fall back to extracting any
         printable ASCII runs of 4+ characters — degraded but still real
         text pulled from the actual blob, never a fabricated string.
      3. If neither yields anything, return "" (empty) rather than
         inventing placeholder text — an unreadable notification is
         reported as such, not silently skipped as if it never existed
         (the caller still logs its existence with a raw byte count).
    """
    if not payload:
        return ""

    try:
        decoded = payload.decode("utf-16-le", errors="ignore")
        stripped = re.sub(r"<[^>]+>", " ", decoded)
        stripped = re.sub(r"\s+", " ", stripped).strip()
        # Filter out control characters / non-printable junk that can
        # survive a UTF-16 decode of binary framing bytes.
        cleaned = "".join(ch for ch in stripped if ch.isprintable())
        if len(cleaned) >= 4:
            return cleaned
    except Exception:
        pass

    try:
        ascii_runs = re.findall(rb"[\x20-\x7e]{4,}", payload)
        joined = " ".join(run.decode("ascii", errors="ignore") for run in ascii_runs)
        return joined.strip()
    except Exception:
        return ""


# Same "explainable, rule-based, not a black box" philosophy as
# email_poller.py's score_message() and ai-agent/correlation/rules_engine.py.
URGENCY_WORDS = {"urgent", "verify your account", "password expires", "act now",
                  "suspended", "security alert", "unusual sign-in", "click here"}
SUSPICIOUS_APP_PATTERNS = ("update", "helper", "assistant", "cleaner", "optimizer")


def score_notification(app_name: str, text: str) -> tuple[float, list[str]]:
    """Pure function, easy to unit test — same design as email_poller's
    score_message(). Returns (confidence 0..1, reasons[])."""
    lowered_text = (text or "").lower()
    lowered_app = (app_name or "").lower()
    reasons: list[str] = []
    score = 0.0

    hits = [w for w in URGENCY_WORDS if w in lowered_text]
    if hits:
        score += min(0.5, 0.15 * len(hits))
        reasons.append(f"Urgency/security-pressure language: {', '.join(hits)}")

    if any(pattern in lowered_app for pattern in SUSPICIOUS_APP_PATTERNS) and not lowered_app.startswith("microsoft"):
        score += 0.2
        reasons.append(f"App name '{app_name}' matches a common fake-utility naming pattern")

    url_count = len(re.findall(r"https?://", lowered_text))
    if url_count:
        score += min(0.3, 0.15 * url_count)
        reasons.append(f"Notification contains {url_count} link(s)")

    return round(min(score, 0.95), 3), reasons


def _load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            logger.warning(f"Could not read state file '{STATE_FILE}' — starting from scratch.")
    return {"last_seen_id": 0}


def _save_state(state: dict) -> None:
    try:
        STATE_FILE.write_text(json.dumps(state))
    except OSError as exc:
        logger.warning(f"Could not save poller state ({exc}) — next run may reprocess some notifications.")


def read_new_notifications(last_seen_id: int) -> list[dict]:
    """
    Reads real, new notifications from a fresh snapshot of wpndatabase.db.
    Returns a list of dicts: {id, app_name, text, arrival_time}. NEVER
    raises on a per-row problem — a single malformed row is logged and
    skipped, the rest of the batch still gets processed. Raises only on
    a whole-database-level failure (file not found, can't open as SQLite
    at all), since that's a real condition the caller must know about.
    """
    snapshot_path = _snapshot_database()
    results = []

    try:
        conn = sqlite3.connect(f"file:{snapshot_path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Schema per public reverse-engineering of wpndatabase.db (Windows
        # 10/11). See module docstring: unofficial, may not match every
        # build. We check for the table's existence first so an
        # unexpected schema fails with a clear message, not a cryptic
        # sqlite3.OperationalError deep in a loop.
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='Notification'"
        )
        if not cursor.fetchone():
            raise RuntimeError(
                "wpndatabase.db does not contain the expected 'Notification' "
                "table — the schema may have changed on this Windows version. "
                "See this module's docstring."
            )

        # Schema CONFIRMED against a real Windows 11 wpndatabase.db (user-
        # verified, 2026-08-24): NotificationHandler's primary key is
        # RecordId, not Id — Notification.HandlerId joins against that.
        # (Original guess used h.Id, which doesn't exist on this build —
        # fixed here based on the real PRAGMA table_info() output.)
        cursor.execute(
            """
            SELECT n.Id, n.HandlerId, n.Payload, n.ArrivalTime, h.PrimaryId
            FROM Notification n
            LEFT JOIN NotificationHandler h ON n.HandlerId = h.RecordId
            WHERE n.Id > ?
            ORDER BY n.Id ASC
            """,
            (last_seen_id,),
        )

        for row in cursor.fetchall():
            try:
                notif_id = row["Id"]
                app_name = row["PrimaryId"] or f"handler_{row['HandlerId']}"
                payload = row["Payload"]
                text = _extract_text_from_payload(payload) if payload else ""
                arrival_dt = _filetime_to_datetime(row["ArrivalTime"])

                results.append({
                    "id": notif_id,
                    "app_name": app_name,
                    "text": text,
                    "arrival_time": arrival_dt.isoformat() if arrival_dt else None,
                    "raw_payload_bytes": len(payload) if payload else 0,
                })
            except Exception as exc:
                logger.warning(f"Skipping malformed notification row: {exc}")
                continue

        conn.close()
    finally:
        try:
            snapshot_path.unlink(missing_ok=True)
        except Exception:
            pass  # best-effort cleanup only, never fails the poll itself

    return results


def get_admin_token() -> str:
    resp = requests.post(
        f"{API_BASE}/login",
        data={"employee_id": ADMIN_USERNAME, "password": ADMIN_PASSWORD},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    if "token" not in body:
        raise RuntimeError(f"Login response had no 'token' field: {body}")
    return body["token"]


def post_ingest_notification(token: str, app_name: str, text: str, confidence: float,
                              reasons: list[str], arrival_time: Optional[str]) -> None:
    resp = requests.post(
        f"{API_BASE}/ingest/notification",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "app_name": app_name, "text": text, "confidence": confidence,
            "reasons": reasons, "arrival_time": arrival_time,
        },
        timeout=10,
    )
    if resp.status_code >= 400:
        logger.warning(f"Ingest failed ({resp.status_code}): {resp.text}")
    else:
        try:
            risk_flag_id = resp.json().get("risk_flag_id")
        except Exception:
            risk_flag_id = None
        logger.info(f"Risk flag created: {risk_flag_id} — {app_name}")


CONFIDENCE_THRESHOLD = 0.3  # matches email_poller.py's threshold for consistency


def poll_once(token: str, state: dict) -> dict:
    last_seen_id = state.get("last_seen_id", 0)
    notifications = read_new_notifications(last_seen_id)

    if not notifications:
        logger.info("No new notifications.")
        return state

    highest_id_seen = last_seen_id
    for notif in notifications:
        highest_id_seen = max(highest_id_seen, notif["id"])

        if not notif["text"]:
            logger.info(f"Notification {notif['id']} from '{notif['app_name']}' had "
                        f"no extractable text ({notif['raw_payload_bytes']} raw bytes) — skipping scoring.")
            continue

        confidence, reasons = score_notification(notif["app_name"], notif["text"])
        logger.info(f"Notification {notif['id']} from '{notif['app_name']}' — score={confidence}")

        if confidence >= CONFIDENCE_THRESHOLD:
            post_ingest_notification(
                token,
                app_name=notif["app_name"],
                text=notif["text"],
                confidence=confidence,
                reasons=reasons,
                arrival_time=notif["arrival_time"],
            )

    state["last_seen_id"] = highest_id_seen
    return state


def main() -> None:
    missing = [name for name, val in [
        ("SENTRY_EMPLOYEE_USERNAME", ADMIN_USERNAME), ("SENTRY_EMPLOYEE_PASSWORD", ADMIN_PASSWORD),
    ] if not val]
    if missing:
        logger.error(f"Missing required env vars: {', '.join(missing)}. See module docstring.")
        return

    try:
        _wpndb_path()  # raises early and clearly if not on Windows
    except RuntimeError as exc:
        logger.error(str(exc))
        return

    logger.info(f"Logging into {API_BASE} as {ADMIN_USERNAME}...")
    token = get_admin_token()
    logger.info("Got token. Starting Windows notification poll loop...")
    logger.info(f"Reading from: {_wpndb_path()}")

    state = _load_state()

    while True:
        try:
            state = poll_once(token, state)
            _save_state(state)
        except FileNotFoundError as exc:
            logger.error(str(exc))
        except RuntimeError as exc:
            logger.error(f"Database schema issue: {exc}")
        except requests.RequestException as exc:
            logger.error(f"API request failed ({exc}) — will retry, refreshing token.")
            try:
                token = get_admin_token()
            except Exception:
                pass
        except Exception as exc:
            logger.error(f"Unexpected error in poll loop: {exc}")

        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()