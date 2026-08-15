"""
confidence_scorer.py
---------------------
Combines multiple signal confidences into one overall score, per
ARCHITECTURE.md §2. This is the reusable, standalone version of the same
noisy-OR math already inlined in services/correlation_engine.py's
combined_confidence() — split out here as its own module so:
  - It can be unit-tested in isolation (tests/test_confidence_scorer.py)
  - Other future callers (e.g. a batch re-scoring job, or the ai-agent/
    module) can reuse the exact same math without importing the whole
    correlation engine
  - The scoring METHOD is swappable in one place if the team later wants
    to try a different combination strategy (see ScoringStrategy below)
    without touching correlation_engine.py's control flow

IMPORTANT: services/correlation_engine.py is what's actually wired into
the live API right now (see main.py) and is NOT changed by this file's
existence — this is a reusable utility, not a replacement. If the team
wants correlation_engine.py to delegate here instead of keeping its own
copy of the math, that's a safe, optional follow-up refactor, not a
requirement for the demo to work.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict

from models import Evidence


class ScoringStrategy(str, Enum):
    """
    NOISY_OR (default, matches correlation_engine.py exactly): treats each
    piece of evidence as an independent "miss" probability and combines
    them so several weak signals can outweigh one strong one — this is
    how a human analyst reasons ("many small clues beat one loud clue").

    MAX: takes the single highest-confidence signal and ignores the rest.
    Useful as a sanity-check comparison ("what if we only trusted our
    single best signal?") but NOT used by the live pipeline — noisy-OR is
    almost always more representative of real correlated attacks, since
    it rewards corroboration across independent sources.
    """
    NOISY_OR = "noisy_or"
    MAX = "max"


@dataclass
class ScoreBreakdown:
    combined_confidence: float
    strategy: ScoringStrategy
    per_evidence_contribution: Dict[str, float]
    evidence_count: int
    source_count: int


def _noisy_or(evidence: List[Evidence]) -> float:
    """Matches services/correlation_engine.py's combined_confidence() bit
    for bit — this IS that same formula, just packaged as a standalone,
    independently testable function."""
    product_of_misses = 1.0
    for ev in evidence:
        product_of_misses *= (1.0 - max(0.0, min(1.0, ev.confidence)))
    return round(1.0 - product_of_misses, 3)


def _max_confidence(evidence: List[Evidence]) -> float:
    return round(max((max(0.0, min(1.0, ev.confidence)) for ev in evidence), default=0.0), 3)


def score(
    evidence: List[Evidence],
    strategy: ScoringStrategy = ScoringStrategy.NOISY_OR,
) -> ScoreBreakdown:
    """
    Main entry point. Returns not just the final number but a full
    breakdown — useful for the "why did you score it this way?" Q&A
    moment, and for any future debug/admin view that wants to show how
    much each individual piece of evidence contributed.
    """
    if not evidence:
        return ScoreBreakdown(
            combined_confidence=0.0,
            strategy=strategy,
            per_evidence_contribution={},
            evidence_count=0,
            source_count=0,
        )

    if strategy == ScoringStrategy.MAX:
        combined = _max_confidence(evidence)
    else:
        combined = _noisy_or(evidence)

    contributions = {ev.id: round(max(0.0, min(1.0, ev.confidence)), 3) for ev in evidence}
    source_count = len(set(ev.source_type for ev in evidence))

    return ScoreBreakdown(
        combined_confidence=combined,
        strategy=strategy,
        per_evidence_contribution=contributions,
        evidence_count=len(evidence),
        source_count=source_count,
    )


def severity_from_confidence(confidence: float) -> str:
    """
    Kept identical to services/correlation_engine.py's thresholds and
    ai-agent/agent_config.yaml's severity_thresholds, so all three copies
    of this logic across the codebase never drift apart.
    """
    if confidence >= 0.85:
        return "critical"
    if confidence >= 0.65:
        return "high"
    if confidence >= 0.40:
        return "medium"
    return "low"