"""
db/json_store.py
-----------------
A real, file-backed key-value store used for Orgs, AdminUsers, and (when
DEMO_MODE/no Postgres) Alerts. Unlike the pure in-memory `STORE` dict in
main.py, this is visible to MULTIPLE PROCESSES on the same machine — which
is required because the IMAP poller (services/email_poller.py) runs as its
own `python email_poller.py` process, separate from `uvicorn main:app`.

Design:
  - One JSON file per collection: data/orgs.json, data/admins.json,
    data/alerts.json (relative to backend/).
  - Every read-modify-write is wrapped in a cross-process file lock
    (filelock) so the API process and the poller process never corrupt
    each other's writes if they happen to write at the same instant.
  - Every function is defensive: a missing/corrupt file is treated as an
    empty collection rather than raising, so the app never fails to boot
    because of a stray file. This mirrors the "never crash mid-demo"
    philosophy already used in db/database.py.

This module is intentionally dumb (no ORM, no schema migration) — it is
the "simple but real" persistence layer for org/admin data, as opposed to
the Postgres-or-memory path already used for demo Alert seeding.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from filelock import FileLock

logger = logging.getLogger("sentry.json_store")

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
_DATA_DIR.mkdir(exist_ok=True)


def _paths(name: str) -> tuple[Path, Path]:
    data_path = _DATA_DIR / f"{name}.json"
    lock_path = _DATA_DIR / f"{name}.json.lock"
    return data_path, lock_path


def _read_raw(name: str) -> dict[str, Any]:
    data_path, _ = _paths(name)
    if not data_path.exists():
        return {}
    try:
        with data_path.open("r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(f"Could not read {data_path} ({exc}) — treating as empty.")
        return {}


def _write_raw(name: str, payload: dict[str, Any]) -> None:
    data_path, _ = _paths(name)
    tmp_path = data_path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    tmp_path.replace(data_path)  # atomic on POSIX + Windows


def load_all(name: str) -> dict[str, Any]:
    """Read the full collection. Safe to call from either process."""
    _, lock_path = _paths(name)
    with FileLock(str(lock_path), timeout=5):
        return _read_raw(name)


def save_one(name: str, key: str, record: dict[str, Any]) -> None:
    """Upsert a single record by key (read-modify-write under lock)."""
    _, lock_path = _paths(name)
    with FileLock(str(lock_path), timeout=5):
        payload = _read_raw(name)
        payload[key] = record
        _write_raw(name, payload)


def delete_one(name: str, key: str) -> None:
    _, lock_path = _paths(name)
    with FileLock(str(lock_path), timeout=5):
        payload = _read_raw(name)
        payload.pop(key, None)
        _write_raw(name, payload)


def find_one(name: str, predicate) -> dict[str, Any] | None:
    """Return the first record where predicate(record) is True, or None."""
    for record in load_all(name).values():
        if predicate(record):
            return record
    return None
