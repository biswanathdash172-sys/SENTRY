"""
services/email_cache.py
-----------------------
Tiny in-process cache that the email_poller.py writes to and
/emails/recent reads from — this is the correct architecture so
the API route never opens its own IMAP connection.

DESIGN INTENT (see Flag 2 in the review notes):
  - email_poller.py (the long-lived background process) is the
    ONLY component that talks to Gmail/IMAP. It writes scored
    emails here after each poll cycle.
  - /emails/recent (the API route) reads from this cache instead
    of opening its own IMAP connection. This prevents:
      1. IMAP TLS handshake latency per API call
      2. Gmail "suspicious login" lockout from rapid logins
      3. Race conditions when polling every 3 seconds

Thread safety: a threading.Lock guards the list so concurrent
FastAPI requests and the background poller thread can't corrupt
the list simultaneously.

The cache holds the last MAX_CACHED_EMAILS entries. Old entries
are evicted in FIFO order once the limit is reached. This is a
simple, correct approach for a demo — a production system would
use Redis or a DB-backed queue instead.
"""

import json
import logging
from pathlib import Path
import threading
from typing import List, Dict, Any

logger = logging.getLogger("sentry.email_cache")

MAX_CACHED_EMAILS = 200
_CACHE_FILE = Path(__file__).resolve().parent.parent / "db" / "email_cache.json"

_lock = threading.Lock()
_cache: List[Dict[str, Any]] = []
_last_mtime: float = 0.0


def _load_disk_cache() -> List[Dict[str, Any]]:
    global _last_mtime
    if _CACHE_FILE.exists():
        try:
            _last_mtime = _CACHE_FILE.stat().st_mtime
            with open(_CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception as e:
            logger.debug(f"Could not load email cache from disk: {e}")
    return []


def _save_disk_cache(data: List[Dict[str, Any]]) -> None:
    global _last_mtime
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        if _CACHE_FILE.exists():
            _last_mtime = _CACHE_FILE.stat().st_mtime
    except Exception as e:
        logger.debug(f"Could not save email cache to disk: {e}")


def write_emails(emails: List[Dict[str, Any]]) -> None:
    """
    Called by email_poller.py and gmail_poller.py after each poll
    cycle. Merges newest emails (deduplicating by 'id' and preserving
    newest-to-oldest order) and trims to MAX_CACHED_EMAILS.
    Persists to disk so FastAPI process can read it instantly.
    """
    if not emails:
        return
    try:
        with _lock:
            global _cache
            disk_data = _load_disk_cache()
            existing_ids = {e.get("id") for e in disk_data if "id" in e}
            new_entries = []
            seen_in_batch = set()
            for e in emails:
                eid = e.get("id")
                if eid and eid not in existing_ids and eid not in seen_in_batch:
                    new_entries.append(e)
                    seen_in_batch.add(eid)
            combined = new_entries + disk_data
            _cache = combined[:MAX_CACHED_EMAILS]
            _save_disk_cache(_cache)
    except Exception as exc:
        logger.debug(f"email_cache write error: {exc}")


def read_emails(max_results: int = 50) -> List[Dict[str, Any]]:
    """
    Called by /emails/recent. Returns up to max_results cached
    emails, most recent first. Checks disk mtime to ensure cross-process
    writes from background pollers are immediately visible.
    """
    with _lock:
        global _cache, _last_mtime
        if _CACHE_FILE.exists():
            current_mtime = _CACHE_FILE.stat().st_mtime
            if not _cache or current_mtime != _last_mtime:
                _cache = _load_disk_cache()
        elif not _cache:
            _cache = _load_disk_cache()
        return list(_cache[:max_results])


def is_populated() -> bool:
    """Quick check: has the poller written anything yet?"""
    with _lock:
        global _cache, _last_mtime
        if _CACHE_FILE.exists():
            current_mtime = _CACHE_FILE.stat().st_mtime
            if not _cache or current_mtime != _last_mtime:
                _cache = _load_disk_cache()
        return len(_cache) > 0

