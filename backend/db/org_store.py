"""
db/org_store.py
----------------
Org + AdminUser persistence, built on the generic JSON file store
(db/json_store.py). This is where the "one admin per org" rule is
actually enforced — not just documented.
"""

from __future__ import annotations

from typing import Optional

from db import json_store
from models import Org, AdminUser

ORGS = "orgs"
ADMINS = "admins"


# ---------------------------------------------------------------------------
# Orgs
# ---------------------------------------------------------------------------
def create_org(name: str, monitored_mailbox: str) -> Org:
    org = Org(name=name, monitored_mailbox=monitored_mailbox)
    json_store.save_one(ORGS, org.id, org.model_dump(mode="json"))
    return org


def get_org(org_id: str) -> Optional[Org]:
    raw = json_store.load_all(ORGS).get(org_id)
    return Org(**raw) if raw else None


def get_org_by_mailbox(mailbox: str) -> Optional[Org]:
    raw = json_store.find_one(ORGS, lambda o: o.get("monitored_mailbox") == mailbox)
    return Org(**raw) if raw else None


# ---------------------------------------------------------------------------
# Admins
# ---------------------------------------------------------------------------
def admin_exists_for_org(org_id: str) -> bool:
    """Enforces the one-admin-per-org rule."""
    return json_store.find_one(ADMINS, lambda a: a.get("org_id") == org_id) is not None


def get_admin_by_username(username: str) -> Optional[AdminUser]:
    raw = json_store.find_one(ADMINS, lambda a: a.get("username") == username)
    return AdminUser(**raw) if raw else None


def create_admin(org_id: str, username: str, password_hash: str) -> AdminUser:
    admin = AdminUser(org_id=org_id, username=username, password_hash=password_hash)
    json_store.save_one(ADMINS, admin.id, admin.model_dump(mode="json"))
    return admin
