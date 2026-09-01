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

from __future__ import annotations

import threading
from typing import List, Dict, Any

MAX_CACHED_EMAILS = 200

_lock = threading.Lock()
_cache: List[Dict[str, Any]] = []


def write_emails(emails: List[Dict[str, Any]]) -> None:
    """
    Called by email_poller.py and gmail_poller.py after each poll
    cycle. Prepends the newest emails (deduplicating by 'id') and
    trims to MAX_CACHED_EMAILS. Never raises — a cache write
    failure must never crash the poller.
    """
    if not emails:
        return
    try:
        with _lock:
            existing_ids = {e["id"] for e in _cache}
            new_entries = [e for e in emails if e.get("id") not in existing_ids]
            # Newest first
            combined = new_entries + _cache
            _cache[:] = combined[:MAX_CACHED_EMAILS]
    except Exception:
        pass  # Cache write failure is non-fatal


def read_emails(max_results: int = 50) -> List[Dict[str, Any]]:
    """
    Called by /emails/recent. Returns up to max_results cached
    emails, most recent first. Returns [] if cache is empty (e.g.
    poller hasn't run yet) — the caller handles this gracefully.
    """
    with _lock:
        return list(_cache[:max_results])


def is_populated() -> bool:
    """Quick check: has the poller written anything yet?"""
    with _lock:
        return len(_cache) > 0
