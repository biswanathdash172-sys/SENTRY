"""
models.py
---------
Lightweight in-memory data shapes for the SENTRY demo backend.

NOTE (hackathon scope): ARCHITECTURE.md specifies a full Postgres schema
(alerts, evidence, playbook_actions, credentials, audit_log). For the demo
build we keep everything in-memory (see demo_data.py) so the app runs with
zero setup and can NEVER fail during a live judging session for lack of a
DB connection. Swapping this layer for real Postgres later is a drop-in
change: replace the STORE dict access in main.py with SQLAlchemy calls —
the Pydantic shapes below already match the schema in ARCHITECTURE.md §5,
so routers/services do not need to change.
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
    attack_chain: List[str] = []          # plain-English step-by-step narrative
    playbook: List[PlaybookAction] = []
    audit_log: List[AuditEntry] = []


class MediaVerifyRequest(BaseModel):
    filename: str
    claimed_sender: Optional[str] = None
    # Demo hook: lets the frontend/judges force a verdict for a repeatable
    # demo without depending on a real ML model being loaded correctly.
    force_verdict: Optional[Literal["authentic", "deepfake", "unsigned"]] = None


class MediaVerifyResult(BaseModel):
    filename: str
    signature_valid: bool
    signer: Optional[str] = None
    deepfake_likelihood: float  # 0.0 - 1.0
    verdict: Literal["authentic", "suspicious", "deepfake", "unsigned"]


class ActionDecision(BaseModel):
    approved_by: Optional[str] = "analyst_demo_user"
