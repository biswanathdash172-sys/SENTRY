"""
models.py
---------
Lightweight in-memory data shapes for the SENTRY demo backend.
"""

from pydantic import BaseModel, Field
from typing import List, Optional, Literal
from datetime import datetime
import uuid

SourceType = Literal["media", "identity", "network", "endpoint", "email"]
Severity = Literal["low", "medium", "high", "critical"]
RiskLevel = Literal["low", "high"]
ActionMode = Literal["auto", "manual", "approved", "denied"]


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: new_id("ev"))
    source_type: SourceType
    description: str
    confidence: float  # 0.0 - 1.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PlaybookAction(BaseModel):
    id: str = Field(default_factory=lambda: new_id("act"))
    label: str
    risk_level: RiskLevel
    mode: ActionMode = "manual"


class AuditEntry(BaseModel):
    id: str = Field(default_factory=lambda: new_id("audit"))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    message: str


class Alert(BaseModel):
    id: str = Field(default_factory=lambda: new_id("alert"))
    title: str
    severity: Severity
    status: Literal["open", "resolved"] = "open"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    evidence: List[Evidence] = []
    attack_chain: List[str] = []
    playbook: List[PlaybookAction] = []
    audit_log: List[AuditEntry] = []


class MediaVerifyRequest(BaseModel):
    filename: str
    claimed_sender: Optional[str] = None
    force_verdict: Optional[Literal["authentic", "deepfake", "unsigned"]] = None


class MediaVerifyResult(BaseModel):
    filename: str
    signature_valid: bool
    signer: Optional[str] = None
    deepfake_likelihood: float
    verdict: Literal["authentic", "suspicious", "deepfake", "unsigned"]


class ActionDecision(BaseModel):
    approved_by: Optional[str] = "analyst_demo_user"


# ---------------------------------------------------------------------------
# NEW — request shapes for the /ingest/* routes (Biswanath, Priority 0)
# ---------------------------------------------------------------------------
class IngestRequest(BaseModel):
    """
    Generic shape for all /ingest/* endpoints. Each connector-style route
    (email/identity/network/endpoint) accepts this same shape and turns it
    into a normal Evidence object, so it flows through the EXISTING
    correlation_engine.correlate() unchanged — no separate ingestion path.
    """
    description: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    title_hint: Optional[str] = None