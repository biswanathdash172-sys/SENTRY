"""
services/domain_verifier.py
-----------------------------
Trusted sender domain whitelist verification with hybrid Supabase + local storage.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sentry.domain_verifier")

_LOCAL_WL_PATH = Path(__file__).resolve().parent.parent / "db" / "local_whitelist.json"
_LOCAL_WHITELIST: dict[str, list[str]] = {}


def _load_local_whitelist() -> dict[str, list[str]]:
    global _LOCAL_WHITELIST
    if _LOCAL_WL_PATH.exists():
        try:
            with open(_LOCAL_WL_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    _LOCAL_WHITELIST = data
                    return _LOCAL_WHITELIST
        except Exception:
            pass
    return _LOCAL_WHITELIST



def _save_local_whitelist() -> None:
    try:
        _LOCAL_WL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_LOCAL_WL_PATH, "w", encoding="utf-8") as f:
            json.dump(_LOCAL_WHITELIST, f, indent=2)
    except Exception as e:
        logger.warning(f"Could not persist local whitelist file: {e}")


@dataclass
class DomainVerifyResult:
    trusted: bool
    domain: str
    reason: str


_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})>?$")


def extract_domain(email_address: str) -> Optional[str]:
    if not email_address:
        return None
    match = _DOMAIN_RE.search(email_address)
    if match:
        return match.group(1).lower()
    parts = email_address.strip().split("@")
    if len(parts) == 2:
        domain = parts[1].rstrip(">").strip().lower()
        if "." in domain:
            return domain
    return None


def get_trusted_domains(org_id: str) -> list[str]:
    # 1. Try Supabase
    try:
        from services.supabase_service import _get_client
        client = _get_client()
        result = (
            client.table("domain_whitelist")
            .select("domain")
            .eq("org_id", org_id)
            .execute()
        )
        if result.data is not None:
            return [row["domain"].lower() for row in result.data]
    except Exception:
        pass

    # 2. Fallback to local store
    wl = _load_local_whitelist()
    return wl.get(org_id, [])


def verify_email_sender(sender: str, org_id: str) -> DomainVerifyResult:
    domain = extract_domain(sender)
    if not domain:
        return DomainVerifyResult(
            trusted=False,
            domain="",
            reason=f"Could not parse domain from sender '{sender}'.",
        )

    trusted_domains = get_trusted_domains(org_id)
    if not trusted_domains:
        return DomainVerifyResult(
            trusted=False,
            domain=domain,
            reason="No trusted domains configured for this org.",
        )

    is_trusted = domain in trusted_domains
    return DomainVerifyResult(
        trusted=is_trusted,
        domain=domain,
        reason=(
            f"Domain '{domain}' is in the org trusted whitelist."
            if is_trusted
            else f"Domain '{domain}' is NOT in the org trusted whitelist."
        ),
    )
