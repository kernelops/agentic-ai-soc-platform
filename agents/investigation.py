"""
Investigation node — the core reasoning agent (two-phase).

Phase A (no LLM): run a prescribed sequence of evidence tools — correlation
context, login history, user baseline — then build an evidence summary and
retrieve candidate MITRE ATT&CK techniques. Running the tools as ordinary async
code (rather than an LLM tool-calling loop) keeps the model turn free for a clean
structured-output call and avoids the Groq structured-output/tool-calling
channel conflict.

Phase B (one LLM call): synthesize the gathered evidence into an
InvestigationOutput — timeline, baseline comparison, matched techniques, and a
folded-in verdict (true/false positive) with confidence and final severity.

The raw evidence bundle is stored on the state so the Verification agent can
independently re-check the conclusion against the same facts.
"""

from __future__ import annotations

import json
import logging

from agents.context import describe_enriched
from agents.llm import structured_invoke
from agents.persistence import update_case
from agents.state import PipelineState
from agents.tools import (
    check_user_baseline,
    get_correlation_context,
    get_login_history,
    query_mitre_attack,
)
from common.config import settings
from common.models import CaseStatus, InvestigationOutput, Verdict

logger = logging.getLogger("soc.agents.investigation")

_SYSTEM = (
    "You are a Tier-2 SOC investigator. You are given an alert, its enrichment, "
    "and an evidence bundle already gathered from the environment (correlation, "
    "login history, user baseline, and candidate MITRE ATT&CK techniques). "
    "Reason step by step over ONLY this evidence and produce a structured "
    "investigation:\n"
    "- timeline: ordered factual events you can support from the evidence\n"
    "- baseline_comparison: how this compares to the user's normal behavior\n"
    "- matched_mitre_techniques: the candidate techniques that GENUINELY fit the "
    "evidence (drop any that don't); each as {technique_id, name}\n"
    "- verdict: true_positive or false_positive\n"
    "- confidence_score: 0.0-1.0\n"
    "- final_severity: 1-10 (may differ from triage now that you have evidence)\n"
    "- evidence_summary and reasoning: concise justification.\n\n"
    "Calibrate the verdict to the STRENGTH of the evidence — do not over-call:\n"
    "- A matched correlation pattern (brute_force, brute_force_then_login, "
    "priv_esc_after_login) plus supporting login history is strong evidence for "
    "true_positive.\n"
    "- Repeated failed logins from one source IP ARE a brute-force attack "
    "(T1110) on their own — a successful login is NOT required.\n"
    "- A privilege escalation shortly after a successful login by the same user "
    "is a strong true_positive (T1548).\n"
    "- With NO correlation pattern and only one or two failed logins, prefer "
    "false_positive or a low-confidence verdict — a lone failed login is routine.\n"
    "Do not invent facts not present in the evidence."
)


def _build_evidence_summary(enriched, login_history: dict) -> str:
    """Assemble a keyword-rich summary that drives MITRE retrieval."""
    a = enriched.alert
    parts = [
        a.rule_description,
        " ".join(a.rule_groups),
        enriched.correlation.pattern_matched.replace("_", " "),
        enriched.correlation.details,
    ]
    if login_history.get("failed_logins", 0) >= settings.brute_force_threshold:
        parts.append("brute force repeated failed password authentication failed")
    if login_history.get("successful_logins", 0) > 0:
        parts.append("successful login accepted password valid account")
    return " ".join(p for p in parts if p)


async def investigation_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    enriched = state["enriched"]
    alert = enriched.alert
    triage = state.get("triage")

    # --- Phase A: gather evidence (prescribed tool sequence, no LLM) ---
    correlation_ev = get_correlation_context(enriched.correlation)
    login_history = await get_login_history(
        user=alert.user, source_ip=alert.source_ip, reference_ts=alert.timestamp
    )
    baseline = await check_user_baseline(user=alert.user, exclude_case_id=case_id)
    evidence_summary = _build_evidence_summary(enriched, login_history)
    mitre_candidates = query_mitre_attack(evidence_summary)

    evidence_bundle = {
        "correlation": correlation_ev,
        "login_history": login_history,
        "user_baseline": baseline,
        "mitre_candidates": mitre_candidates,
    }

    # --- Phase B: synthesize into a verdict (one structured LLM call) ---
    triage_line = (
        f"Triage said: type={triage.alert_type.value}, severity={triage.initial_severity}."
        if triage else "Triage output unavailable."
    )
    messages = [
        ("system", _SYSTEM),
        ("human",
         describe_enriched(enriched)
         + f"\n\n{triage_line}\n\n## Evidence bundle\n"
         + json.dumps(evidence_bundle, indent=2, default=str)
         + "\n\nInvestigate and return your structured findings with a verdict."),
    ]

    try:
        investigation = await structured_invoke(InvestigationOutput, messages, what="investigation")
    except Exception as exc:  # noqa: BLE001 - safe default routes to reporting, never remediation
        logger.warning("Investigation LLM failed for case %s, defaulting to UNVERIFIED: %r", case_id, exc)
        investigation = InvestigationOutput(
            evidence_summary=evidence_summary,
            verdict=Verdict.UNVERIFIED,
            confidence_score=0.0,
            final_severity=triage.initial_severity if triage else alert.rule_level,
            reasoning="Investigation LLM unavailable; routed to reporting without a positive verdict.",
        )

    logger.info(
        "Investigation case %s | verdict=%s confidence=%.2f severity=%d mitre=%s",
        case_id, investigation.verdict.value, investigation.confidence_score,
        investigation.final_severity,
        [t.get("technique_id") for t in investigation.matched_mitre_techniques],
    )

    # True positives head to verification; everything else (FP/UNVERIFIED) reports out.
    next_status = (
        CaseStatus.VERIFYING
        if investigation.verdict == Verdict.TRUE_POSITIVE
        else CaseStatus.REPORTING
    )
    await update_case(case_id, status=next_status, investigation=investigation)
    return {
        "investigation": investigation,
        "evidence_bundle": evidence_bundle,
        "current_stage": next_status.value,
    }
