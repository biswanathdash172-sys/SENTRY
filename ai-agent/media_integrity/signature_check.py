"""
signature_check.py
-------------------
Standalone cryptographic signature verification for the media integrity
module, per ARCHITECTURE.md §4. Mirrors the signature-check half of
backend/services/media_integrity_service.py, split out here so the AI
agent module can be developed/tested without importing the FastAPI app.

DEMO MODE: uses a toy in-memory registry, same approach and same
intentional honesty as backend/services/media_integrity_service.py — see
that file's docstring for the full "why this is the right call for a
hackathon" reasoning. Swapping this for a real PKI / credential-registry
lookup later only means replacing SIGNED_REGISTRY + verify_signature()
below; nothing downstream needs to change.
"""

from dataclasses import dataclass
from typing import Optional, Dict

# Toy "signing registry" — filenames present here are treated as validly
# signed by that person. In a real system this would be a lookup against
# an actual PKI / credential registry service (see revocation_registry.py
# for the companion "has this credential been revoked?" check).
SIGNED_REGISTRY: Dict[str, str] = {
    "quarterly_update_signed.mp4": "CFO Office (verified)",
    "board_memo_q3_signed.pdf": "General Counsel (verified)",
}


@dataclass
class SignatureResult:
    filename: str
    signature_valid: bool
    signer: Optional[str] = None


def verify_signature(filename: str) -> SignatureResult:
    """
    Looks up whether `filename` has a valid signature on record. Case-
    insensitive to avoid a trivial "just change the case" bypass in a demo
    click-through.
    """
    signer = SIGNED_REGISTRY.get(filename.lower())
    return SignatureResult(
        filename=filename,
        signature_valid=signer is not None,
        signer=signer,
    )


def register_signed_file(filename: str, signer: str) -> None:
    """
    Demo/testing helper: lets a teammate register a new "signed" file at
    runtime without editing this file, e.g. for a live Q&A demo where a
    judge wants to see the authentic-verdict path with a fresh filename.
    """
    SIGNED_REGISTRY[filename.lower()] = signer