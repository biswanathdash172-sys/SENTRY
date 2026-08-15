"""
ml_correlator.py
-----------------
Optional ML-STYLE correlator — a STRETCH GOAL per ARCHITECTURE.md §4, not
required for a working demo. rules_engine.py is the primary, demo-safe
correlation path actually wired into the live system.

HONESTY NOTE (read this before claiming anything to a judge): this is NOT
a trained machine-learning model. There is no training data, no model
file, no inference call. It's a transparent weighted-scoring function —
each source_type gets a configurable weight (see agent_config.yaml), and
the score is a weighted combination of signal confidences instead of the
plain noisy-OR used in rules_engine.py. This is a reasonable "ML-flavored"
upgrade path (feature weights are exactly what you'd start learning if you
trained a real logistic-regression correlator later), but calling it more
than that would be overclaiming — see WALKTHROUGH.md Part C's guidance on
honest scoping.

Kept disabled by default (agent_config.yaml: ml_correlator.enabled=false)
so the live pipeline always uses the explainable rules_engine.py path.
"""

from dataclasses import dataclass
from typing import List, Dict
import math

from correlation.rules_engine import SignalEvent, severity_from_confidence

# Default weights if agent_config.yaml isn't loaded (keeps this module
# runnable standalone without a YAML parser dependency for quick tests).
DEFAULT_SOURCE_WEIGHTS: Dict[str, float] = {
    "media": 1.0,
    "email": 0.8,
    "identity": 0.7,
    "network": 0.6,
    "endpoint": 0.6,
}


@dataclass
class WeightedCorrelationResult:
    confidence: float
    severity: str
    per_signal_contribution: Dict[str, float]


def weighted_confidence(
    events: List[SignalEvent],
    source_weights: Dict[str, float] = None,
) -> WeightedCorrelationResult:
    """
    Combines signals using a weighted, saturating sum instead of the plain
    noisy-OR in rules_engine.py. Each source_type's weight reflects how
    much that channel matters for THIS project's threat model (media
    authenticity is weighted highest, since it's the flagship differentiator
    per EXPLANATION.md §1 Problem B).

    Uses a smooth saturation function (1 - e^-x) so confidence approaches
    but never exceeds 1.0, no matter how many signals pile in — avoids the
    "5 weak signals magically become 100% certain" failure mode.
    """
    weights = source_weights or DEFAULT_SOURCE_WEIGHTS

    if not events:
        return WeightedCorrelationResult(confidence=0.0, severity="low", per_signal_contribution={})

    contributions: Dict[str, float] = {}
    total = 0.0
    for ev in events:
        weight = weights.get(ev.source_type, 0.5)  # unknown source -> modest default weight
        contribution = weight * max(0.0, min(1.0, ev.confidence))
        contributions[ev.id] = round(contribution, 3)
        total += contribution

    # Saturating transform: keeps result in (0, 1) regardless of how many
    # signals are summed, and rewards additional corroborating evidence
    # with diminishing returns rather than linear/unbounded growth.
    confidence = round(1 - math.exp(-total), 3)

    return WeightedCorrelationResult(
        confidence=confidence,
        severity=severity_from_confidence(confidence),
        per_signal_contribution=contributions,
    )


def explain_weights(source_weights: Dict[str, float] = None) -> str:
    """
    Small helper for Q&A / demo narration: prints out the weight table in
    plain English, so a teammate can answer "why did media weigh more than
    network?" on the spot without digging through code.
    """
    weights = source_weights or DEFAULT_SOURCE_WEIGHTS
    lines = ["Source weight table (higher = more influence on confidence):"]
    for source, weight in sorted(weights.items(), key=lambda kv: -kv[1]):
        lines.append(f"  {source:10s} -> {weight}")
    return "\n".join(lines)