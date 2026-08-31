"""
correlation_engine.py
----------------------
Groups raw evidence into ONE explained alert with a plain-English attack
chain. Rule-based, explainable, no training data or GPU needed.
"""

from typing import List
from models import Evidence, new_id

SOURCE_LABELS = {
    "media": "Media authenticity signal",
    "identity": "Identity / login signal",
    "network": "Network signal",
    "endpoint": "Endpoint signal",
    "email": "Email signal",
}


def build_attack_chain(evidence: List[Evidence]) -> List[str]:
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


def build_attack_chain_structured(evidence: List[Evidence]) -> List[dict]:
    if not evidence:
        return []
    
    ordered = sorted(evidence, key=lambda e: e.timestamp)
    return [
        {
            'step': i,
            'source': ev.source_type,
            'event': ev.description,
            'evidence_id': ev.id
        }
        for i, ev in enumerate(ordered, start=1)
    ]


def combined_confidence(evidence: List[Evidence]) -> float:
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


def classify_evidence_impact(evidence: Evidence) -> str:
    if evidence.confidence >= 0.7:
        return "High"
    if evidence.confidence >= 0.4:
        return "Medium"
    return "Low"

def explain_risk(evidence: List[Evidence], severity: str) -> str:
    factors = ", ".join(f"{e.source_type}({e.impact})" for e in evidence)
    return f"Risk = {severity.upper()} because of {factors}"

def correlate(evidence: List[Evidence], title_hint: str = "Correlated Alert") -> dict:
    for ev in evidence:
        ev.impact = classify_evidence_impact(ev)
        
    confidence = combined_confidence(evidence)
    severity = severity_from_confidence(confidence)
    risk_explanation = explain_risk(evidence, severity)
    
    return {
        "title": title_hint,
        "severity": severity,
        "risk_explanation": risk_explanation,
        "evidence": evidence,
        "attack_chain": build_attack_chain(evidence),
        "attack_chain_structured": build_attack_chain_structured(evidence)
    }