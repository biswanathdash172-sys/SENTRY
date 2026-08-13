"""
media_integrity_service.py
---------------------------
Wraps "signature check" + "deepfake scan" and returns a verdict + Evidence
object, per ARCHITECTURE.md §4 and §7 (flagship deepfake-CFO demo flow).

DEMO MODE / FALLBACK: This hackathon build does not ship a trained deepfake
model (ARCHITECTURE.md explicitly calls this a stretch goal). Instead it
uses a deterministic heuristic over the filename + an optional
`force_verdict` override, so the flagship demo is 100% repeatable and can
never fail/crash in front of judges because a model failed to load.
Swapping in a real model later only means replacing `_heuristic_deepfake_score`
below — everything upstream (Evidence, correlation, playbook) is unaffected.
"""

import hashlib
from typing import Optional
from models import MediaVerifyRequest, MediaVerifyResult, Evidence

# Toy "signing registry" for the demo — filenames present here are treated
# as validly signed by that person.
SIGNED_REGISTRY = {
    "quarterly_update_signed.mp4": "CFO Office (verified)",
}


def _heuristic_deepfake_score(filename: str) -> float:
    """
    Deterministic pseudo-score derived from the filename so repeated calls
    with the same file give the same demo result. Filenames containing
    'deepfake', 'fake', or 'cfo' bias the score upward to make the flagship
    demo reliably trigger — this is clearly a heuristic stand-in, not a
    real classifier.
    """
    lowered = filename.lower()
    bias = 0.0
    if "deepfake" in lowered or "fake" in lowered:
        bias = 0.55
    elif "cfo" in lowered or "urgent" in lowered:
        bias = 0.35

    digest = hashlib.sha256(filename.encode()).hexdigest()
    base = (int(digest[:8], 16) % 1000) / 1000.0 * 0.4  # 0.0 - 0.4 jitter
    return round(min(1.0, base + bias), 3)


def verify_media(req: MediaVerifyRequest) -> MediaVerifyResult:
    signer = SIGNED_REGISTRY.get(req.filename.lower())
    signature_valid = signer is not None

    if req.force_verdict == "authentic":
        return MediaVerifyResult(
            filename=req.filename, signature_valid=True,
            signer=req.claimed_sender or "Verified signer",
            deepfake_likelihood=0.03, verdict="authentic",
        )
    if req.force_verdict == "deepfake":
        return MediaVerifyResult(
            filename=req.filename, signature_valid=False, signer=None,
            deepfake_likelihood=0.94, verdict="deepfake",
        )
    if req.force_verdict == "unsigned":
        return MediaVerifyResult(
            filename=req.filename, signature_valid=False, signer=None,
            deepfake_likelihood=0.22, verdict="unsigned",
        )

    score = _heuristic_deepfake_score(req.filename)
    if signature_valid and score < 0.3:
        verdict = "authentic"
    elif score >= 0.7:
        verdict = "deepfake"
    elif not signature_valid:
        verdict = "unsigned"
    else:
        verdict = "suspicious"

    return MediaVerifyResult(
        filename=req.filename,
        signature_valid=signature_valid,
        signer=signer,
        deepfake_likelihood=score,
        verdict=verdict,
    )


def result_to_evidence(result: MediaVerifyResult) -> Evidence:
    if result.verdict == "authentic":
        desc = f"'{result.filename}' signature verified — signed by {result.signer}."
        confidence = 0.1  # low confidence this is an attack
    else:
        desc = (
            f"'{result.filename}' failed integrity check "
            f"(signed={result.signature_valid}, deepfake_likelihood="
            f"{round(result.deepfake_likelihood * 100)}%)."
        )
        confidence = max(result.deepfake_likelihood, 0.3 if not result.signature_valid else 0.0)

    return Evidence(source_type="media", description=desc, confidence=confidence)
