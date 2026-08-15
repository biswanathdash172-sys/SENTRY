"""
db/database.py
---------------
Postgres persistence layer for SENTRY — designed as a strict DROP-IN per
models.py's original docstring promise: "replace the STORE dict access in
main.py with SQLAlchemy calls — the Pydantic shapes already match the
schema, so routers/services do not need to change."

DEMO-SAFE BY DESIGN (this is the whole point of doing this last, per
BISWANATH_TASKS.txt Priority 2):
  - If DATABASE_URL is unset, unreachable, or DEMO_MODE=true, this module
    NEVER raises — main.py checks `db_available()` once at boot and simply
    keeps using the in-memory STORE dict exactly as before. The app can
    ALWAYS boot with zero DB setup, so a broken DB connection on judging
    day can never take the demo down.
  - When a real Postgres DATABASE_URL IS reachable, every mutation
    (approve/deny/resolve/ingest/simulate) is persisted, so the audit log
    survives a page refresh AND a backend restart — proving the system is
    real, not just in-browser state (this is explicitly called out as a
    goal in ROADMAP.md Day 4).

Storage strategy: one row per Alert, with evidence/attack_chain/playbook/
audit_log stored as a single JSON column (see db/schema.sql for why this
is intentionally simpler than ARCHITECTURE.md's original 5-table plan —
same data, one table, zero migration tooling needed for a hackathon).

Usage from main.py:
    from db import database as db

    db.init_db()                        # call once at startup, never raises
    if db.db_available():
        alerts = db.load_all_alerts()   # dict[str, Alert] or {} if empty
    ...
    db.save_alert(alert)                # best-effort, never raises
"""

from typing import Optional
from datetime import datetime
import json
import logging

from sqlalchemy import create_engine, Column, String, JSON, DateTime, text
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.exc import SQLAlchemyError

import config
from models import Alert

logger = logging.getLogger("sentry.db")

Base = declarative_base()
_engine = None
_SessionLocal = None
_available = False  # set True only after a successful connection + table check


class AlertRow(Base):
    __tablename__ = "alerts"
    id = Column(String(64), primary_key=True)
    title = Column(String, nullable=False)
    severity = Column(String(16), nullable=False)
    status = Column(String(16), nullable=False)
    created_at = Column(DateTime, nullable=False)
    data = Column(JSON, nullable=False)


def init_db() -> None:
    """
    Attempts to connect to DATABASE_URL and ensure the alerts table exists.
    NEVER raises — any failure just leaves db_available() == False, and
    main.py falls back to the in-memory STORE dict, exactly like before
    this module existed.
    """
    global _engine, _SessionLocal, _available

    if config.DEMO_MODE_FORCED:
        logger.info("DEMO_MODE=true — skipping DB entirely, using in-memory STORE.")
        _available = False
        return

    if not config.DATABASE_URL:
        logger.info("No DATABASE_URL set — using in-memory STORE (demo mode).")
        _available = False
        return

    try:
        _engine = create_engine(config.DATABASE_URL, pool_pre_ping=True)
        # Cheap connectivity check before we trust this engine for the whole run.
        with _engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        Base.metadata.create_all(_engine)
        _SessionLocal = sessionmaker(bind=_engine)
        _available = True
        logger.info("Connected to Postgres — persistence enabled.")
    except Exception as exc:
        # Deliberately broad, not just SQLAlchemyError: a missing driver
        # (e.g. psycopg2 not installed) raises ModuleNotFoundError at
        # create_engine() time, not a SQLAlchemyError — and a malformed
        # DATABASE_URL can raise other plain Python exceptions too. ANY
        # failure here must fall back to in-memory STORE, never crash boot.
        logger.warning(f"DB unreachable or misconfigured ({exc}) — falling back to in-memory STORE.")
        _engine = None
        _SessionLocal = None
        _available = False


def db_available() -> bool:
    return _available


def load_all_alerts() -> dict:
    """Returns {alert_id: Alert} from the DB, or {} on any failure."""
    if not _available:
        return {}
    try:
        with _SessionLocal() as session:
            rows = session.query(AlertRow).all()
            result = {}
            for row in rows:
                alert = Alert(**row.data)
                result[alert.id] = alert
            return result
    except (SQLAlchemyError, Exception) as exc:
        logger.warning(f"Failed to load alerts from DB ({exc}) — continuing without them.")
        return {}


def save_alert(alert: Alert) -> bool:
    """
    Upserts one alert. Best-effort: returns False and logs a warning on
    failure instead of raising, so a mutating API call (approve/deny/
    ingest/simulate) can NEVER 500 because the DB hiccuped mid-demo — the
    in-memory STORE in main.py is always updated first and is the source
    of truth for that request either way.
    """
    if not _available:
        return False
    try:
        with _SessionLocal() as session:
            payload = json.loads(alert.model_dump_json())
            row = session.get(AlertRow, alert.id)
            if row is None:
                row = AlertRow(id=alert.id)
                session.add(row)
            row.title = alert.title
            row.severity = alert.severity
            row.status = alert.status
            row.created_at = alert.created_at
            row.data = payload
            session.commit()
        return True
    except (SQLAlchemyError, Exception) as exc:
        logger.warning(f"Failed to persist alert '{alert.id}' to DB ({exc}) — in-memory copy is still updated.")
        return False