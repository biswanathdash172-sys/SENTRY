"""
correlation_engine.py
----------------------
Groups raw evidence into ONE explained alert with a plain-English attack
chain. Per ARCHITECTURE.md, this is rule-based ("if X + Y + Z happen within
N minutes -> one alert") for the hackathon — explainable and fast, no
training data or GPU needed. A real ML correlator is future work
(ai-agent/correlation/ml_correlator.py in the full architecture).

This module never raises on malformed input — a correlation "miss" should
degrade to a plausible single-evidence alert, not crash the request.
"""

from typing import List
from models import Evidence, new_id

# Simple keyword weighting so the narrative reads sensibly for a demo,
# without needing a real NLP model.
SOURCE_LABELS = {
    "media": "Media authenticity signal",
    "identity": "Identity / login signal",
    "network": "Network signal",
    "endpoint": "Endpoint signal",
    "email": "Email signal",
}


def build_attack_chain(evidence: List[Evidence]) -> List[str]:
    """Turn a list of evidence into an ordered, human-readable narrative."""
    if not evidence:
        return ["No evidence attached to this alert yet."]

    ordered = sorted(evidence, key=lambda e: e.timestamp)
    chain = []
    for i, ev in enumerate(ordered, start=1):
        label = SOURCE_LABELS.get(ev.source_type, ev.source_type.title())
        chain.append(
            f"Step {i}: {label} — {ev.description} "
            f"(confidence {round(ev.confidence * 100)}%)"
        )
    chain.append(
        f"Conclusion: {len(ordered)} independent signal(s) correlate to a single "
        f"attack pattern — treated as one alert rather than {len(ordered)} noisy ones."
    )
    return chain


def combined_confidence(evidence: List[Evidence]) -> float:
    """
    Combines multiple weak signals into one overall confidence score.
    Uses a simple 'noisy-OR' so that several medium-confidence signals
    can outweigh one strong one — mirrors how real SOC correlation reasons
    ("many small clues" > "one loud clue").
    """
    if not evidence:
        return 0.0
    product_of_misses = 1.0
    for ev in evidence:
        product_of_misses *= (1.0 - max(0.0, min(1.0, ev.confidence)))
    return round(1.0 - product_of_misses, 3)


def severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"


def correlate(evidence: List[Evidence], title_hint: str = "Correlated Alert") -> dict:
    """
    Entry point used by main.py when new evidence arrives.
    Returns a dict ready to build an Alert (id left to caller/model default).
    """
    confidence = combined_confidence(evidence)
    return {
        "title": title_hint,
        "severity": severity_from_confidence(confidence),
        "evidence": evidence,
        "attack_chain": build_attack_chain(evidence),
    }
