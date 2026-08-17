"""
store.py
--------
Shared in-memory STORE + Postgres bootstrap, extracted out of main.py so
that routers/*.py can import it without a circular import (main.py ->
routers -> main.py would fail otherwise).

Behavior is UNCHANGED from the original main.py — this is a pure move,
not a rewrite:
  - DB reachable AND has existing alerts  -> load them.
  - DB reachable but empty (first boot)    -> seed demo data, persist it.
  - DB unreachable / DEMO_MODE=true        -> in-memory STORE, seeded
    fresh every boot. Never fails.

Usage from routers:
    from store import STORE, get_alert_or_404
    from db import database as db
    ... db.save_alert(alert) after mutating STORE ...
"""

from fastapi import HTTPException

from models import Alert
from demo_data import seed_alerts
from db import database as db

db.init_db()

if db.db_available():
    STORE: dict[str, Alert] = db.load_all_alerts()
    if not STORE:
        STORE = seed_alerts()
        for seeded_alert in STORE.values():
            db.save_alert(seeded_alert)
else:
    STORE: dict[str, Alert] = seed_alerts()


def get_alert_or_404(alert_id: str) -> Alert:
    alert = STORE.get(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return alert