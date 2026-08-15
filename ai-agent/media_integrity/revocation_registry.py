"""
revocation_registry.py
-----------------------
Checks whether a signing credential has been revoked, per
ARCHITECTURE.md §4. This is the third leg of the media-integrity check,
alongside signature_check.py (is it signed at all?) and deepfake_scan.py
(does the content itself look synthetic?).

A credential can be validly signed (signature_check.py returns True) but
still untrustworthy if it's since been revoked (e.g. an employee who left
the company, or a compromised signing key that was pulled). Checking this
separately — rather than baking it into signature_check.py — mirrors
ARCHITECTURE.md §5's separate `credentials` table (status: active/revoked)
and keeps each check single-purpose and easy to explain individually.

DEMO MODE: toy in-memory registry, same intentional pattern as the rest of
this module (see signature_check.py docstring).
"""

from dataclasses import dataclass
from typing import Dict, Optional

# signer_name -> status. Anyone not in this dict is assumed "active"
# (never explicitly revoked) — matches ARCHITECTURE.md §5's credentials
# table default. Add a name here with status "revoked" to simulate a
# pulled/compromised credential in a demo.
CREDENTIAL_REGISTRY: Dict[str, str] = {
    "CFO Office (verified)": "active",
    "General Counsel (verified)": "active",
    # Example of a revoked credential, useful for demoing the "signed but
    # revoked" edge case live if a judge asks about it:
    "Former IT Admin (verified)": "revoked",
}


@dataclass
class RevocationResult:
    signer: str
    status: str  # "active" | "revoked" | "unknown"
    is_revoked: bool


def check_revocation(signer: Optional[str]) -> RevocationResult:
    """
    Returns the current revocation status for a given signer name. A
    signer of None (i.e. an unsigned file — signature_check.py already
    returned no signer) is reported as "unknown" rather than "active",
    since there's nothing to check — this keeps the three-way status
    honest instead of defaulting an absent signer to "trustworthy".
    """
    if not signer:
        return RevocationResult(signer="", status="unknown", is_revoked=False)

    status = CREDENTIAL_REGISTRY.get(signer, "active")
    return RevocationResult(
        signer=signer,
        status=status,
        is_revoked=(status == "revoked"),
    )


def revoke_credential(signer: str) -> None:
    """
    Demo/testing helper + the real action `playbook_engine`'s "Revoke
    signing credential" high-risk action would call in a production
    build, once an analyst approves it. For the hackathon, this just
    flips the in-memory registry entry — the important part is that it's
    a distinct, named function an approval flow can call, not that it's
    wired to a real PKI revocation API yet.
    """
    CREDENTIAL_REGISTRY[signer] = "revoked"