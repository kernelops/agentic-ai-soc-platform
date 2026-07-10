"""
Remediation node — drafts a response for verified true positives.

Retrieves the matching runbook (RAG stub for now) and drafts specific, targeted
actions — block THIS source IP, disable THIS account, isolate THIS host — each
flagged destructive or not. It only PROPOSES; nothing executes here. Destructive
actions are gated by the Approval node downstream.
"""

from __future__ import annotations

import json
import logging

from agents.llm import structured_invoke
from agents.persistence import update_case
from agents.state import PipelineState
from agents.tools import query_runbooks
from common.models import (
    CaseStatus,
    RemediationAction,
    RemediationOutput,
)

logger = logging.getLogger("soc.agents.remediation")

_SYSTEM = (
    "You are a SOC remediation planner. Given a verified true-positive incident "
    "and the matching response runbook, draft specific proposed_actions that "
    "target the actual entities in this alert (the source IP, the user account, "
    "the hostname). For each action set: action (e.g. block_ip, disable_account, "
    "isolate_host, raise_severity), target (the concrete IP/user/host), "
    "is_destructive (true for anything that blocks/disables/isolates), and a short "
    "details string. You PROPOSE only — never assume execution. Reference the "
    "runbook id in runbook_reference."
)


def _fallback_from_runbook(runbook: dict, alert) -> RemediationOutput:
    """Build proposed actions directly from the runbook if the LLM is unavailable."""
    target_for = {
        "block_ip": alert.source_ip,
        "disable_account": alert.user,
        "isolate_host": alert.hostname,
        "snapshot_host": alert.hostname,
    }
    actions = [
        RemediationAction(
            action=rec["action"],
            target=target_for.get(rec["action"], ""),
            is_destructive=rec.get("is_destructive", False),
            details=f"From runbook {runbook.get('runbook_id', '')}",
        )
        for rec in runbook.get("recommended_actions", [])
    ]
    return RemediationOutput(
        proposed_actions=actions,
        runbook_reference=runbook.get("runbook_id", ""),
        reasoning="Drafted directly from runbook (remediation LLM unavailable).",
    )


async def remediation_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    alert = state["enriched"].alert
    triage = state.get("triage")
    investigation = state.get("investigation")

    alert_type = triage.alert_type.value if triage else "unknown"
    runbook = query_runbooks(alert_type)

    messages = [
        ("system", _SYSTEM),
        ("human",
         f"Alert entities: source_ip={alert.source_ip or 'n/a'}, user={alert.user or 'n/a'}, "
         f"hostname={alert.hostname or 'n/a'}.\n"
         f"Verdict: true_positive (severity {investigation.final_severity if investigation else 'n/a'}).\n"
         f"Matched MITRE: {json.dumps(investigation.matched_mitre_techniques if investigation else [])}\n\n"
         f"## Runbook\n{json.dumps(runbook, indent=2)}\n\n"
         "Draft the concrete proposed remediation actions for this specific incident."),
    ]

    try:
        remediation = await structured_invoke(RemediationOutput, messages, what="remediation")
        if not remediation.proposed_actions:  # empty draft — fall back to runbook
            remediation = _fallback_from_runbook(runbook, alert)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Remediation LLM failed for case %s, using runbook fallback: %r", case_id, exc)
        remediation = _fallback_from_runbook(runbook, alert)

    destructive = [a.action for a in remediation.proposed_actions if a.is_destructive]
    logger.info(
        "Remediation case %s | runbook=%s actions=%d destructive=%s",
        case_id, remediation.runbook_reference,
        len(remediation.proposed_actions), destructive or "none",
    )
    await update_case(case_id, status=CaseStatus.REMEDIATING, remediation=remediation)
    return {"remediation": remediation, "current_stage": CaseStatus.REMEDIATING.value}
