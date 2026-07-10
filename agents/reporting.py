"""
Reporting node — always runs, finalizes the case.

Produces the analyst-facing incident report for EVERY alert regardless of the
path taken (false positive, rejected by verification, or verified true positive),
so the dashboard has a documented reasoning trail for every case.

Verdict, severity, matched techniques, remediation summary and approval status
are set deterministically from the upstream outputs (not left to the LLM); the
LLM writes the narrative summary, evidence chain, and recommendations. The node
then writes the final report and closes the case (or leaves it pending approval).
"""

from __future__ import annotations

import json
import logging

from agents.llm import structured_invoke
from agents.persistence import update_case
from agents.state import PipelineState
from common.models import CaseStatus, IncidentReport, Verdict

logger = logging.getLogger("soc.agents.reporting")

_SYSTEM = (
    "You are a SOC analyst writing the final incident report. Given the full case "
    "trail, write: a concise summary (2-4 sentences), an evidence_chain (ordered "
    "list of the key facts that drove the outcome), and recommendations (next "
    "steps for a human analyst). Be factual and grounded in the provided data."
)


def _final_verdict(state: PipelineState) -> Verdict:
    verification = state.get("verification")
    investigation = state.get("investigation")
    if verification is not None and not verification.verified:
        return Verdict.REJECTED
    if investigation is not None:
        return investigation.verdict
    return Verdict.UNVERIFIED


def _remediation_summary(state: PipelineState) -> str:
    remediation = state.get("remediation")
    if not remediation or not remediation.proposed_actions:
        return "No remediation proposed."
    acts = ", ".join(f"{a.action}({a.target})" for a in remediation.proposed_actions)
    status = state.get("approval_status", "not_required")
    prefix = {
        "pending": "Proposed, pending human approval",
        "auto_approved": "Auto-approved (non-destructive)",
    }.get(status, "Proposed")
    return f"{prefix}: {acts} [runbook {remediation.runbook_reference}]"


async def reporting_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    enriched = state["enriched"]
    investigation = state.get("investigation")
    triage = state.get("triage")

    # Deterministic fields (never left to the LLM).
    verdict = _final_verdict(state)
    severity = (
        investigation.final_severity if investigation
        else triage.initial_severity if triage
        else enriched.alert.rule_level
    )
    mitre = [
        f"{t.get('technique_id', '')} {t.get('name', '')}".strip()
        for t in (investigation.matched_mitre_techniques if investigation else [])
    ]
    approval_status = state.get("approval_status", "not_required")
    remediation_taken = _remediation_summary(state)

    trail = {
        "triage": triage.model_dump() if triage else None,
        "investigation": investigation.model_dump() if investigation else None,
        "verification": state["verification"].model_dump() if state.get("verification") else None,
        "remediation": state["remediation"].model_dump() if state.get("remediation") else None,
        "final_verdict": verdict.value,
    }
    messages = [
        ("system", _SYSTEM),
        ("human", "## Case trail\n" + json.dumps(trail, indent=2, default=str)
         + "\n\nWrite the incident report."),
    ]

    try:
        drafted = await structured_invoke(IncidentReport, messages, what="reporting")
        report = drafted.model_copy(update={
            "verdict": verdict, "severity": severity,
            "matched_mitre_techniques": mitre, "remediation_taken": remediation_taken,
            "approval_status": approval_status,
        })
    except Exception as exc:  # noqa: BLE001
        logger.warning("Reporting LLM failed for case %s, using templated report: %r", case_id, exc)
        report = IncidentReport(
            summary=f"{enriched.alert.rule_description} on {enriched.alert.hostname or 'unknown host'} "
                    f"— verdict {verdict.value}.",
            severity=severity, verdict=verdict, matched_mitre_techniques=mitre,
            remediation_taken=remediation_taken, approval_status=approval_status,
            evidence_chain=[enriched.correlation.details] if enriched.correlation.details else [],
        )

    final_status = (
        CaseStatus.PENDING_APPROVAL if approval_status == "pending" else CaseStatus.CLOSED
    )
    logger.info(
        "Report case %s | verdict=%s severity=%d status=%s",
        case_id, verdict.value, severity, final_status.value,
    )
    await update_case(case_id, status=final_status, report=report)
    return {"report": report, "current_stage": final_status.value}
