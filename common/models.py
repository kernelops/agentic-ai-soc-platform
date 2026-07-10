"""
Shared Pydantic models for the Agentic AI SOC Platform.

Every layer in the pipeline imports from here to ensure consistent
data shapes across ingestion, correlation, enrichment, and agents.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional, Union

from pydantic import BaseModel, BeforeValidator, Field


# ---------------------------------------------------------------------------
# Lenient numeric/bool types for LLM-populated fields
# ---------------------------------------------------------------------------
# Groq/Llama structured output sometimes emits numbers/bools as strings
# (e.g. "initial_severity": "1"). Groq validates the tool call against the
# JSON schema *server-side* and rejects a string where the schema says integer,
# before Pydantic can coerce it. Typing these fields as Union[..., str] widens
# the JSON schema to accept the string, and the BeforeValidator coerces it back
# to the real type. Non-LLM code still reads plain int/float/bool at runtime.

def _coerce_int(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return int(float(v.strip()))
        except (ValueError, TypeError):
            return 0
    return v


def _coerce_float(v: Any) -> Any:
    if isinstance(v, str):
        try:
            return float(v.strip())
        except (ValueError, TypeError):
            return 0.0
    return v


def _coerce_bool(v: Any) -> Any:
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "y")
    return v


LenientInt = Annotated[Union[int, str], BeforeValidator(_coerce_int)]
LenientFloat = Annotated[Union[float, str], BeforeValidator(_coerce_float)]
LenientBool = Annotated[Union[bool, str], BeforeValidator(_coerce_bool)]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AlertType(str, Enum):
    AUTH_FAILURE = "auth_failure"
    PRIV_ESCALATION = "priv_escalation"
    FILE_INTEGRITY = "file_integrity"
    NETWORK_ANOMALY = "network_anomaly"
    DATA_ACCESS = "data_access"
    UNKNOWN = "unknown"


class CaseStatus(str, Enum):
    INGESTED = "ingested"
    CORRELATING = "correlating"
    ENRICHING = "enriching"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    DECIDING = "deciding"
    VERIFYING = "verifying"
    REMEDIATING = "remediating"
    PENDING_APPROVAL = "pending_approval"
    REPORTING = "reporting"
    CLOSED = "closed"


class Verdict(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNVERIFIED = "unverified"
    REJECTED = "rejected"


# ---------------------------------------------------------------------------
# Wazuh raw alert shape (what arrives from the webhook)
# ---------------------------------------------------------------------------

class WazuhRule(BaseModel):
    level: int = 0
    description: str = ""
    id: str = ""
    groups: list[str] = Field(default_factory=list)


class WazuhAgent(BaseModel):
    id: str = ""
    name: str = ""
    ip: str = ""


class WazuhAlert(BaseModel):
    """Raw Wazuh alert JSON as received from the webhook."""
    id: str = ""
    timestamp: str = ""
    rule: WazuhRule = Field(default_factory=WazuhRule)
    agent: WazuhAgent = Field(default_factory=WazuhAgent)
    data: dict[str, Any] = Field(default_factory=dict)
    location: str = ""
    full_log: str = ""


# ---------------------------------------------------------------------------
# Normalized internal alert
# ---------------------------------------------------------------------------

class NormalizedAlert(BaseModel):
    """Internal alert schema — the canonical representation used throughout the pipeline."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str = ""
    dest_ip: str = ""
    user: str = ""
    hostname: str = ""
    rule_id: str = ""
    rule_level: int = 0
    rule_description: str = ""
    rule_groups: list[str] = Field(default_factory=list)
    location: str = ""
    full_log: str = ""
    raw_payload: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Correlation context (attached by the Correlation Engine)
# ---------------------------------------------------------------------------

class CorrelationContext(BaseModel):
    related_alert_count: int = 0
    pattern_matched: str = ""  # e.g., "brute_force", "brute_force_then_login"
    time_window_minutes: float = 0.0
    related_alert_ids: list[str] = Field(default_factory=list)
    details: str = ""


# ---------------------------------------------------------------------------
# Enrichment context (attached by the Enrichment Engine)
# ---------------------------------------------------------------------------

class OTXReputation(BaseModel):
    is_known_malicious: bool = False
    pulse_count: int = 0
    reputation_score: int = 0
    tags: list[str] = Field(default_factory=list)
    country: str = ""


class EnrichmentContext(BaseModel):
    otx_reputation: Optional[OTXReputation] = None
    asset_criticality: str = "unknown"  # critical, high, medium, low, unknown
    historical_case_count: int = 0
    historical_cases: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Enriched alert (what enters the agentic layer)
# ---------------------------------------------------------------------------

class EnrichedAlert(BaseModel):
    """Fully enriched alert ready for the agentic pipeline."""
    alert: NormalizedAlert
    correlation: CorrelationContext = Field(default_factory=CorrelationContext)
    enrichment: EnrichmentContext = Field(default_factory=EnrichmentContext)


# ---------------------------------------------------------------------------
# Agent outputs
# ---------------------------------------------------------------------------

class TriageOutput(BaseModel):
    alert_type: AlertType = AlertType.UNKNOWN
    initial_severity: LenientInt = 1  # 1-10
    reasoning: str = ""


class InvestigationOutput(BaseModel):
    evidence_summary: str = ""
    timeline: list[str] = Field(default_factory=list)
    baseline_comparison: str = ""
    matched_mitre_techniques: list[dict[str, str]] = Field(default_factory=list)
    verdict: Verdict = Verdict.UNVERIFIED
    confidence_score: LenientFloat = 0.0
    final_severity: LenientInt = 1
    reasoning: str = ""


class VerificationOutput(BaseModel):
    verified: LenientBool = False
    confidence_score: LenientFloat = 0.0
    rejection_reason: str = ""
    evidence_check: str = ""
    mitre_check: str = ""
    policy_check: str = ""


class RemediationAction(BaseModel):
    action: str = ""  # e.g., "block_ip", "disable_account", "isolate_host"
    target: str = ""  # e.g., the IP or username
    is_destructive: LenientBool = False
    details: str = ""


class RemediationOutput(BaseModel):
    proposed_actions: list[RemediationAction] = Field(default_factory=list)
    runbook_reference: str = ""
    reasoning: str = ""


class IncidentReport(BaseModel):
    summary: str = ""
    severity: LenientInt = 1
    verdict: Verdict = Verdict.UNVERIFIED
    evidence_chain: list[str] = Field(default_factory=list)
    matched_mitre_techniques: list[str] = Field(default_factory=list)
    remediation_taken: str = ""
    approval_status: str = ""
    recommendations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Case document (the full MongoDB document for one incident)
# ---------------------------------------------------------------------------

class CaseDocument(BaseModel):
    """One document per case in MongoDB — accumulates data as the pipeline progresses."""
    case_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    status: CaseStatus = CaseStatus.INGESTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Pipeline data (populated progressively by each stage)
    alert: Optional[NormalizedAlert] = None
    correlation: Optional[CorrelationContext] = None
    enrichment: Optional[EnrichmentContext] = None
    triage: Optional[TriageOutput] = None
    investigation: Optional[InvestigationOutput] = None
    verification: Optional[VerificationOutput] = None
    remediation: Optional[RemediationOutput] = None
    approval: Optional[dict[str, Any]] = None  # {required, status, requested_at/decided_at}
    report: Optional[IncidentReport] = None

    # Feedback loop
    analyst_feedback: Optional[str] = None
    analyst_corrected_verdict: Optional[Verdict] = None
    feedback_timestamp: Optional[datetime] = None
