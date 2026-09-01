"""
services/device_agent.py
-------------------------
SENTRY Device Agent — runs on an employee's machine alongside notification_poller.py.
Polls the SENTRY backend for active device freeze orders and executes them silently.

FREEZE MECHANISM (Windows only):
  When status="active" is received, this calls Windows' LockWorkStation()
  via ctypes — the screen locks immediately with no dialog or warning.
  The lock screen is the standard Windows lock screen with no SENTRY branding.
  The employee can unlock it with their Windows password as normal; SENTRY's
  freeze only means the NEXT poll (30s later) will lock again if the admin
  hasn't lifted the freeze in the meantime.

HOW TO RUN:
  python services/device_agent.py

REQUIRED ENV:
  SENTRY_API_BASE             — backend URL (default: http://localhost:8000)
  SENTRY_EMPLOYEE_USERNAME    — employee's own Employee ID (not "admin" — each
                                employee runs this as themselves)
  SENTRY_EMPLOYEE_PASSWORD    — that employee's password

POLLING INTERVAL:
  FREEZE_POLL_INTERVAL_SECONDS (default: 30)
  Lower is faster response; higher is less battery drain. 30s is a reasonable
  balance — sub-minute response time while being background-friendly.

PLATFORM:
  Only performs the actual LockWorkStation call on Windows. On Linux/macOS it
  logs what WOULD happen but doesn't call any OS API — so the code is safe
  to test on any platform.
"""

from __future__ import annotations

import logging
import os
import platform
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [device-agent] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentry.device_agent")

API_BASE = os.environ.get("SENTRY_API_BASE", "http://localhost:8000")
EMPLOYEE_USERNAME = os.environ.get("SENTRY_EMPLOYEE_USERNAME", "") or os.environ.get("SENTRY_ADMIN_USERNAME", "")
EMPLOYEE_PASSWORD = os.environ.get("SENTRY_EMPLOYEE_PASSWORD", "") or os.environ.get("SENTRY_ADMIN_PASSWORD", "")
POLL_INTERVAL = int(os.environ.get("FREEZE_POLL_INTERVAL_SECONDS", "30"))

_IS_WINDOWS = platform.system() == "Windows"

_last_freeze_id: str | None = None  # Track last freeze we acted on to avoid repeat locks


def _lock_workstation() -> None:
    """
    Silently locks the Windows workstation. No dialog, no warning.
    On non-Windows, logs the action instead.
    """
    if _IS_WINDOWS:
        try:
            import ctypes
            result = ctypes.windll.user32.LockWorkStation()
            if result:
                logger.info("Workstation LOCKED by SENTRY device agent (LockWorkStation called).")
            else:
                logger.warning("LockWorkStation returned 0 — may have failed. Check event log.")
        except Exception as exc:
            logger.error(f"LockWorkStation call failed: {exc}")
    else:
        logger.info("[SIMULATED on non-Windows] Workstation would be locked now.")


def get_employee_token() -> str:
    resp = requests.post(
        f"{API_BASE}/login",
        data={"employee_id": EMPLOYEE_USERNAME, "password": EMPLOYEE_PASSWORD},
        timeout=10,
    )
    resp.raise_for_status()
    body = resp.json()
    for key in ("token", "access_token", "accessToken", "jwt"):
        if key in body:
            return body[key]
    raise RuntimeError(f"No token in /login response: {list(body.keys())}")


def check_freeze_status(token: str) -> dict:
    """Polls GET /device/freeze-status. Never raises — returns {} on error."""
    try:
        resp = requests.get(
            f"{API_BASE}/device/freeze-status",
            headers={"Authorization": f"Bearer {token}"},
            timeout=8,
        )
        if resp.status_code == 401:
            raise RuntimeError("Token expired — re-auth needed.")
        resp.raise_for_status()
        return resp.json()
    except RuntimeError:
        raise
    except Exception as exc:
        logger.debug(f"Freeze status check failed (non-fatal): {exc}")
        return {}


def main() -> None:
    global _last_freeze_id

    if not EMPLOYEE_USERNAME or not EMPLOYEE_PASSWORD:
        logger.error(
            "SENTRY_EMPLOYEE_USERNAME and SENTRY_EMPLOYEE_PASSWORD must be set in .env. "
            "Each employee should set these to their OWN credentials."
        )
        sys.exit(1)

    logger.info(
        f"SENTRY Device Agent starting — employee={EMPLOYEE_USERNAME}, "
        f"backend={API_BASE}, poll_interval={POLL_INTERVAL}s"
    )

    token: str = ""
    try:
        token = get_employee_token()
        logger.info("Authentication successful. Monitoring for freeze orders...")
    except Exception as exc:
        logger.error(f"Could not authenticate with SENTRY backend: {exc}")
        sys.exit(1)

    while True:
        try:
            status = check_freeze_status(token)
            frozen = status.get("frozen", False)
            freeze_id = status.get("freeze_id")

            if frozen:
                freeze_status = status.get("status")
                reason = status.get("reason", "")
                logger.warning(
                    f"FREEZE ORDER ACTIVE — id={freeze_id}, status={freeze_status}, "
                    f"reason='{reason[:80]}'"
                )
                # Only lock if this is a NEW freeze order (avoid locking on every poll)
                if freeze_id and freeze_id != _last_freeze_id:
                    _last_freeze_id = freeze_id
                    _lock_workstation()
                else:
                    logger.info(f"Freeze already applied (id={freeze_id}) — not re-locking.")
            else:
                if _last_freeze_id is not None:
                    logger.info("Freeze lifted by admin — device monitoring continues.")
                    _last_freeze_id = None
                else:
                    logger.debug("No active freeze — device clear.")

        except RuntimeError:
            # Token expired — re-authenticate
            logger.info("Token expired. Re-authenticating...")
            try:
                token = get_employee_token()
                logger.info("Re-authentication successful.")
            except Exception as exc:
                logger.error(f"Re-authentication failed: {exc}. Will retry next cycle.")
        except Exception as exc:
            logger.warning(f"Unexpected error in device agent loop: {exc}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
