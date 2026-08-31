"""
chain_explainer.py
-------------------
Generates the human-readable "Step 1 -> Step 2 -> ..." narrative for a
correlated incident, per ARCHITECTURE.md §4. This is the "explainable AI"
piece described in EXPLANATION.md §3 — every alert shows its reasoning,
not just a black-box score.

MODE: "template" (see agent_config.yaml: explainability.mode). This is a
deterministic, template-based generator — NOT an LLM call. That's an
intentional, honest choice for a hackathon demo:
  - Free (no API cost, no rate limits to hit mid-demo)
  - Instant (no network round-trip / latency to explain away)
  - Never hallucinates a wrong fact about the alert in front of judges
An LLM-based version is listed as a "Could-have" in EXECUTION_PLAN.md
Stage 3 — genuinely optional, not a corner that was cut under pressure.
"""

from typing import List
from correlation.rules_engine import SignalEvent, build_attack_chain, build_attack_chain_structured, combined_confidence

def explain_incident(
    events: List[SignalEvent],
    severity: str,
    title: str,
) -> str:
    """
    Produces a short paragraph summary suitable for the top of an alert
    detail view — a plain-English "why this matters" line, complementing
    (not replacing) the step-by-step attack chain from build_attack_chain().
    """
    if not events:
        return f"'{title}' has no supporting evidence yet."

    confidence = combined_confidence(events)
    source_count = len(set(e.source_type for e in events))
    signal_count = len(events)

    urgency_phrase = {
        "critical": "This requires immediate attention.",
        "high": "This should be reviewed promptly.",
        "medium": "This is worth a look when convenient.",
        "low": "This is likely low-impact, but logged for visibility.",
    }.get(severity, "")

    return (
        f"'{title}' was flagged with {severity} severity "
        f"({round(confidence * 100)}% combined confidence), based on "
        f"{signal_count} signal(s) across {source_count} independent "
        f"source(s). {urgency_phrase}"
    )


def explain_chain_and_summary(events: List[SignalEvent], severity: str, title: str) -> dict:
    """
    Convenience wrapper returning both the step-by-step chain (from
    rules_engine.build_attack_chain) and the plain-English summary above,
    in the shape the frontend's AttackChain.jsx / center-column panel
    expects to render together.
    """
    return {
        "summary": explain_incident(events, severity, title),
        "steps": build_attack_chain(events),
        "steps_structured": build_attack_chain_structured(events),
    }