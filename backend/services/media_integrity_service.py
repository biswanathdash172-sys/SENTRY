"""
media_integrity_service.py
---------------------------
Wraps "signature check" + "deepfake scan" and returns a verdict + Evidence
object.
"""

import hashlib
from typing import Optional
from models import MediaVerifyRequest, MediaVerifyResult, Evidence

SIGNED_REGISTRY = {
    "quarterly_update_signed.mp4": "CFO Office (verified)",
    "board_memo_q3_signed.pdf": "General Counsel (verified)",
}


def _heuristic_deepfake_score(filename: str) -> float:
    lowered = filename.lower()
    bias = 0.0
    if "deepfake" in lowered or "fake" in lowered:
        bias = 0.55
    elif "cfo" in lowered or "urgent" in lowered:
        bias = 0.35

    digest = hashlib.sha256(filename.encode()).hexdigest()
    base = (int(digest[:8], 16) % 1000) / 1000.0 * 0.4
    return round(min(1.0, base + bias), 3)


def provenance_label(r: MediaVerifyResult) -> str:
    return 'Verified' if r.signature_valid else 'Not verified'

def forensics_label(r: MediaVerifyResult) -> str:
    if r.deepfake_likelihood >= 0.7:
        return 'Suspicious'
    elif r.deepfake_likelihood >= 0.3:
        return 'Uncertain'
    return 'Normal'


def verify_media(req: MediaVerifyRequest) -> MediaVerifyResult:
    signer = SIGNED_REGISTRY.get(req.filename.lower())
    signature_valid = signer is not None

    result = None
    if req.force_verdict == "authentic":
        result = MediaVerifyResult(
            filename=req.filename, signature_valid=True,
            signer=req.claimed_sender or "Verified signer",
            deepfake_likelihood=0.03, verdict="authentic",
        )
    elif req.force_verdict == "deepfake":
        result = MediaVerifyResult(
            filename=req.filename, signature_valid=False, signer=None,
            deepfake_likelihood=0.94, verdict="deepfake",
        )
    elif req.force_verdict == "unsigned":
        result = MediaVerifyResult(
            filename=req.filename, signature_valid=False, signer=None,
            deepfake_likelihood=0.22, verdict="unsigned",
        )
    else:
        score = _heuristic_deepfake_score(req.filename)
        if signature_valid and score < 0.3:
            verdict = "authentic"
        elif score >= 0.7:
            verdict = "deepfake"
        elif not signature_valid:
            verdict = "unsigned"
        else:
            verdict = "suspicious"

        result = MediaVerifyResult(
            filename=req.filename, signature_valid=signature_valid,
            signer=signer, deepfake_likelihood=score, verdict=verdict,
        )
        
    result.provenance_label = provenance_label(result)
    result.forensics_label = forensics_label(result)
    return result


def result_to_evidence(result: MediaVerifyResult) -> Evidence:
    if result.verdict == "authentic":
        desc = f"'{result.filename}' signature verified — signed by {result.signer}."
        confidence = 0.1
    else:
        desc = (
            f"'{result.filename}' failed integrity check "
            f"(signed={result.signature_valid}, deepfake_likelihood="
            f"{round(result.deepfake_likelihood * 100)}%)."
        )
        confidence = max(result.deepfake_likelihood, 0.3 if not result.signature_valid else 0.0)

    return Evidence(
        source_type="media", 
        description=desc, 
        confidence=confidence,
        provenance_label=result.provenance_label,
        forensics_label=result.forensics_label
    )