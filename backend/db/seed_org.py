"""
db/seed_org.py
---------------
One-off script to pre-create the test Org + Admin, so you don't have to
exercise the invite-only /admin/register flow every time you restart the
demo. Run once:

    cd backend
    python db/seed_org.py

Reads the same env vars the rest of the app uses:
  ADMIN_INVITE_CODE       (required — must match what you'll show as the
                           "invite" in the demo, even though this script
                           bypasses the HTTP endpoint)
  IMAP_USER               used as the org's monitored_mailbox
  SENTRY_ADMIN_USERNAME   default: "admin"
  SENTRY_ADMIN_PASSWORD   default: "ChangeMe123!" (change this)
  SENTRY_ORG_NAME         default: "Sentry Demo Org"

Safe to re-run: if an admin with that username already exists, it does
nothing and just prints the existing org/admin instead of erroring.
"""

from __future__ import annotations

import os
import sys

# Allow running as `python db/seed_org.py` from the backend/ directory.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def load_dotenv(path: str) -> None:
    """Load simple KEY=VALUE entries without requiring python-dotenv."""
    try:
        with open(path, encoding="utf-8") as env_file:
            for line in env_file:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))

from db import org_store
from services import auth_service

ORG_NAME = os.environ.get("SENTRY_ORG_NAME", "Sentry Demo Org")
MONITORED_MAILBOX = os.environ.get("IMAP_USER", "")
ADMIN_USERNAME = os.environ.get("SENTRY_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("SENTRY_ADMIN_PASSWORD", "ChangeMe123!")


def main() -> None:
    if not MONITORED_MAILBOX:
        print("ERROR: set IMAP_USER to the Gmail address this org should monitor.")
        return

    existing = org_store.get_admin_by_username(ADMIN_USERNAME)
    if existing:
        org = org_store.get_org(existing.org_id)
        print(f"Admin '{ADMIN_USERNAME}' already exists for org '{org.name if org else existing.org_id}'. Nothing to do.")
        return

    org, admin = auth_service.register_admin(
        invite_code=auth_service.ADMIN_INVITE_CODE or "seed-script-bypass",
        org_name=ORG_NAME,
        monitored_mailbox=MONITORED_MAILBOX,
        username=ADMIN_USERNAME,
        password=ADMIN_PASSWORD,
    ) if auth_service.ADMIN_INVITE_CODE else _seed_without_http_invite_check()

    print(f"Created org '{org.name}' ({org.id}) monitoring {org.monitored_mailbox}")
    print(f"Created admin '{admin.username}' ({admin.id})")
    print(f"Login with username='{ADMIN_USERNAME}' password='{ADMIN_PASSWORD}' at POST /admin/login")


def _seed_without_http_invite_check():
    """Fallback so the seed script works even if ADMIN_INVITE_CODE isn't
    set yet — it still goes through org_store directly (bypassing the
    invite-code check, which only guards the public HTTP endpoint)."""
    org = org_store.create_org(name=ORG_NAME, monitored_mailbox=MONITORED_MAILBOX)
    admin = org_store.create_admin(
        org_id=org.id, username=ADMIN_USERNAME,
        password_hash=auth_service.hash_password(ADMIN_PASSWORD),
    )
    return org, admin


if __name__ == "__main__":
    main()
