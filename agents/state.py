"""
LangGraph pipeline state.

`PipelineState` carries the enriched alert plus each agent's output as it flows
through the graph. It is `total=False` so every node writes only its own slice;
LangGraph merges deltas with last-write-wins per key (each node owns distinct
keys, so no custom reducers are needed). We keep the actual Pydantic objects in
state (not dicts) and serialize only at the Mongo write boundary.
"""

from __future__ import annotations

from typing import Any, TypedDict

from common.models import (
    EnrichedAlert,
    IncidentReport,
    InvestigationOutput,
    RemediationOutput,
    TriageOutput,
    VerificationOutput,
)


class PipelineState(TypedDict, total=False):
    case_id: str
    enriched: EnrichedAlert            # alert + correlation + enrichment (seed input)

    triage: TriageOutput
    investigation: InvestigationOutput
    evidence_bundle: dict[str, Any]    # Phase-A tool outputs; verification re-reads this
    verification: VerificationOutput
    remediation: RemediationOutput
    approval_status: str               # "pending" | "auto_approved" | "not_required"
    report: IncidentReport

    current_stage: str                 # CaseStatus value the pipeline last reached
    error: str                         # set by a node that failed (isolation)
