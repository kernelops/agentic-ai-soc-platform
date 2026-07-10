"""
Triage node — first LLM call.

A fast, shallow classification: what kind of alert is this and how urgent does it
look on the surface? It does NOT investigate — it reads the alert plus enrichment
(rule level, asset criticality, OTX reputation, correlation pattern) and outputs
an alert_type + initial_severity. Deeper evidence-gathering is the Investigation
agent's job.
"""

from __future__ import annotations

import logging

from agents.context import describe_enriched
from agents.llm import structured_invoke
from agents.persistence import update_case
from agents.state import PipelineState
from common.models import AlertType, CaseStatus, TriageOutput

logger = logging.getLogger("soc.agents.triage")

_SYSTEM = (
    "You are a Tier-1 SOC triage analyst. Classify the alert into exactly one "
    "alert_type and assign an initial_severity from 1 (benign) to 10 (critical), "
    "weighing the Wazuh rule level, asset criticality, threat-intel reputation, "
    "and any correlation pattern. This is a fast surface assessment, not a deep "
    "investigation. Valid alert_type values: auth_failure, priv_escalation, "
    "file_integrity, network_anomaly, data_access, unknown. Give one or two "
    "sentences of reasoning."
)


async def triage_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    enriched = state["enriched"]

    messages = [
        ("system", _SYSTEM),
        ("human", describe_enriched(enriched) + "\n\nClassify this alert and score its initial severity."),
    ]

    try:
        triage = await structured_invoke(TriageOutput, messages, what="triage")
    except Exception as exc:  # noqa: BLE001 - never crash the pipeline on the LLM
        logger.warning("Triage LLM failed for case %s, using rule-level default: %r", case_id, exc)
        # Safe default: map the Wazuh rule level onto a 1-10 severity.
        triage = TriageOutput(
            alert_type=AlertType.UNKNOWN,
            initial_severity=max(1, min(10, enriched.alert.rule_level)),
            reasoning="Triage LLM unavailable; severity derived from Wazuh rule level.",
        )

    logger.info(
        "Triage case %s | type=%s severity=%d",
        case_id, triage.alert_type.value, triage.initial_severity,
    )
    await update_case(case_id, status=CaseStatus.INVESTIGATING, triage=triage)
    return {"triage": triage, "current_stage": CaseStatus.INVESTIGATING.value}
