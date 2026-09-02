"""
services/notification_capture.py
---------------------------------
One-shot, server-triggered Windows notification capture — lets the admin
dashboard's "Run Scan" button pull REAL notifications from the SAME
machine the backend is running on, in addition to the SCA fixed-payload
scan, as a single unified action.

WHY THIS EXISTS: notification_poller.py is designed to run as its own
continuous background process (correct for a real deployment where the
backend runs on a server and each employee's machine runs its own local
poller). But in this project's CURRENT setup — backend and the
employee's machine are the SAME Windows box, both on localhost — it's
more convenient to let one click on the dashboard trigger both real SCA
scanning AND a real one-shot read of whatever's new in Windows'
notification history, instead of needing a second terminal running
notification_poller.py forever.

HONESTY NOTE: if the backend process is NOT running on Windows (e.g. a
future deployment where backend and employee machines really are
separate), this gracefully returns an empty list — it does NOT fabricate
notification data, and does NOT error the whole scan out. The SCA scan
portion of /scan/demo continues to work regardless.

This shares the exact same state file, scoring heuristics, and payload-
parsing code as notification_poller.py by importing it directly — zero
duplicated logic, so both code paths always score identically and never
double-process the same notification (shared last_seen_id state).
"""

from __future__ import annotations
from typing import List
import logging

logger = logging.getLogger("sentry.notification_capture")


def capture_new_notifications_once(min_confidence: float = 0.0) -> List[dict]:
    """
    Attempts ONE pass of reading new Windows notifications from this
    machine's wpndatabase.db, scoring them, and returning any that meet
    or exceed min_confidence.

    Returns [] (never raises to the caller) if:
      - this process is not running on Windows (no LOCALAPPDATA), or
      - the notification database doesn't exist / can't be read, or
      - the schema doesn't match what's expected

    Each dict in the returned list: {app_name, text, confidence, reasons,
    arrival_time} — ready to hand to risk_classifier.classify_confidence()
    and sca_service.persist_scan_result().
    """
    try:
        from services import notification_poller as poller
    except Exception as exc:
        logger.warning(f"Could not import notification_poller module: {exc}")
        return []

    try:
        poller._wpndb_path()
    except RuntimeError as exc:
        logger.info(f"Notification capture skipped (not Windows): {exc}")
        return []

    state = poller._load_state()
    last_seen_id = state.get("last_seen_id", 0)

    try:
        notifications = poller.read_new_notifications(last_seen_id, max_age_hours=24.0)
    except FileNotFoundError as exc:
        logger.info(f"Notification capture skipped: {exc}")
        return []
    except RuntimeError as exc:
        logger.warning(f"Notification capture schema issue: {exc}")
        return []
    except Exception as exc:
        logger.warning(f"Unexpected error reading notifications: {exc}")
        return []

    if not notifications:
        return []

    highest_id_seen = last_seen_id
    results = []
    for notif in notifications:
        highest_id_seen = max(highest_id_seen, notif.get("id", 0))
        if not notif.get("text"):
            continue
        confidence, reasons = poller.score_notification(notif["app_name"], notif["text"])
        if confidence >= min_confidence:
            results.append({
                "id": notif.get("id"),
                "app_name": notif["app_name"],
                "text": notif["text"],
                "confidence": confidence,
                "reasons": reasons,
                "arrival_time": notif["arrival_time"],
            })

    # Advance state if any higher ID seen
    if highest_id_seen > last_seen_id:
        state["last_seen_id"] = highest_id_seen
        poller._save_state(state)

    return results