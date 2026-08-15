"""
agent_config_loader.py
-----------------------
Tiny loader for agent_config.yaml. Deliberately simple and fail-safe: if
the YAML file is missing, malformed, or PyYAML isn't installed, this falls
back to sensible hardcoded defaults instead of raising — the AI agent
module (and any test importing it) must never crash just because a config
file didn't load, same fail-safe philosophy as the rest of this project.

Usage:
    from agent_config_loader import get_config
    cfg = get_config()
    threshold = cfg["media_integrity"]["deepfake_scan"]["deepfake_verdict_threshold"]
"""

import os
from typing import Any, Dict

_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "agent_config.yaml")

# Fallback defaults — kept in exact sync with agent_config.yaml's values,
# so behavior is identical whether or not YAML parsing succeeds.
_DEFAULTS: Dict[str, Any] = {
    "correlation": {
        "rules_engine": {"enabled": True},
        "ml_correlator": {
            "enabled": False,
            "source_weights": {
                "media": 1.0, "email": 0.8, "identity": 0.7,
                "network": 0.6, "endpoint": 0.6,
            },
        },
    },
    "severity_thresholds": {"critical": 0.85, "high": 0.65, "medium": 0.40},
    "media_integrity": {
        "deepfake_scan": {
            "deepfake_verdict_threshold": 0.70,
            "authentic_score_ceiling": 0.30,
        },
        "signature_check": {"enabled": True},
        "revocation_registry": {"enabled": True},
    },
    "playbook": {"unknown_action_default_risk": "high"},
    "explainability": {"mode": "template"},
}

_cached_config: Dict[str, Any] = None


def get_config() -> Dict[str, Any]:
    """Loads and caches agent_config.yaml. Falls back to _DEFAULTS on any
    failure (missing file, missing PyYAML, malformed YAML) — never raises."""
    global _cached_config
    if _cached_config is not None:
        return _cached_config

    try:
        import yaml  # optional dependency; only needed if the YAML file is present
        with open(_CONFIG_PATH, "r") as f:
            loaded = yaml.safe_load(f)
        _cached_config = loaded if loaded else _DEFAULTS
    except Exception:
        # Missing file, missing PyYAML, malformed YAML — all fall back
        # silently to defaults rather than crashing anything downstream.
        _cached_config = _DEFAULTS

    return _cached_config