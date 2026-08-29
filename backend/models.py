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
    confidence: float
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
    org_id: Optional[str] = None
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


class IngestRequest(BaseModel):
    description: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    title_hint: Optional[str] = None


# ---------------------------------------------------------------------------
# Auth identity shape — carried inside a decoded JWT's claims.
# RBAC UPDATE (Option A): is_admin now travels with every authenticated
# request, set once at login time from Supabase's employees.is_admin
# column (see supabase_service.verify_employee_login and
# routers/org_auth.py's employee_login). Defaults to False so any code
# path that forgets to set it explicitly fails CLOSED (non-admin), never
# open — same fail-safe philosophy as risk_classifier.py.
# ---------------------------------------------------------------------------
class AdminUser(BaseModel):
    employee_id: str
    org_id: str
    is_admin: bool = False