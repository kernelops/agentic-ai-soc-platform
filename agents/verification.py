"""
Verification node — the hallucination guard (the project's differentiator).

Runs only on true-positive investigations, before any remediation is reached.
It combines two independent checks:

1. Deterministic policy gate (code): certain privileged accounts
   (settings.agent_no_autoremediate_users, e.g. admin/root) can never be
   auto-remediated — they hard-route to human review regardless of the LLM.

2. Independent LLM re-check: given the RAW evidence bundle and the investigation's
   *claims* (verdict, cited MITRE techniques) — but NOT its persuasive reasoning —
   it re-derives whether the evidence actually supports the verdict and whether
   the cited techniques genuinely match, rather than being retrieved-but-misapplied.

The case is verified only if BOTH pass. Either can veto. A rejection routes the
case to reporting (flagged rejected), never to remediation.
"""

from __future__ import annotations

import json
import logging

from agents.llm import structured_invoke
from agents.persistence import update_case
from agents.state import PipelineState
from common.config import settings
from common.models import CaseStatus, VerificationOutput

logger = logging.getLogger("soc.agents.verification")

_SYSTEM = (
    "You are a senior SOC verification analyst providing an independent second "
    "opinion on another agent's true-positive conclusion. Confirm or reject it "
    "based strictly on whether the RAW evidence supports it. Check:\n"
    "- evidence_check: does the evidence actually support a true-positive verdict?\n"
    "- mitre_check: are the cited MITRE techniques a genuine match, or "
    "retrieved-but-misapplied?\n"
    "- set verified=true when the evidence is coherent and the techniques fit; "
    "verified=false only for genuine overreach, a misapplied technique, or a "
    "policy violation (give a rejection_reason).\n\n"
    "Apply this grounding correctly — do NOT reject on these mistaken bases:\n"
    "- Multiple failed logins from one source IP ARE a brute-force attack "
    "(T1110). A successful login is NOT required to confirm brute force.\n"
    "- brute_force_then_login (failures then a success from the same IP) "
    "indicates likely credential compromise (T1110 + T1078).\n"
    "- A privilege escalation after login by the same user indicates T1548.\n"
    "Do not reject a well-supported true positive merely because more evidence "
    "could theoretically exist. Reject genuine overreach — e.g. a true_positive "
    "claimed from a single failed login with no correlation pattern."
)


async def verification_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    alert = state["enriched"].alert
    investigation = state.get("investigation")
    evidence_bundle = state.get("evidence_bundle", {})

    # --- 1. Deterministic policy gate ---
    blocked_users = {u.lower() for u in settings.agent_no_autoremediate_users}
    policy_blocked = bool(alert.user) and alert.user.lower() in blocked_users

    # --- 2. Independent LLM re-check ---
    claims = {
        "claimed_verdict": investigation.verdict.value if investigation else "unknown",
        "claimed_confidence": investigation.confidence_score if investigation else 0.0,
        "cited_mitre_techniques": investigation.matched_mitre_techniques if investigation else [],
        "claimed_timeline": investigation.timeline if investigation else [],
        "claimed_baseline": investigation.baseline_comparison if investigation else "",
    }
    messages = [
        ("system", _SYSTEM),
        ("human",
         "## Raw evidence\n" + json.dumps(evidence_bundle, indent=2, default=str)
         + "\n\n## Investigator's claims (verify against the evidence above)\n"
         + json.dumps(claims, indent=2, default=str)
         + "\n\nIndependently verify or reject the true-positive conclusion."),
    ]

    try:
        verification = await structured_invoke(VerificationOutput, messages, what="verification")
    except Exception as exc:  # noqa: BLE001 - safe default: reject (never remediate on uncertainty)
        logger.warning("Verification LLM failed for case %s, defaulting to REJECT: %r", case_id, exc)
        verification = VerificationOutput(
            verified=False,
            confidence_score=0.0,
            rejection_reason="Verification LLM unavailable; rejecting so nothing auto-remediates.",
            evidence_check="not performed",
            mitre_check="not performed",
        )

    # --- Combine: either check can veto ---
    if policy_blocked:
        verification.verified = False
        verification.policy_check = "blocked: privileged account requires human review"
        if not verification.rejection_reason:
            verification.rejection_reason = (
                f"Privileged account '{alert.user}' — policy requires human review before remediation."
            )
    else:
        verification.policy_check = verification.policy_check or "no policy violation"

    logger.info(
        "Verification case %s | verified=%s policy_blocked=%s reason=%s",
        case_id, verification.verified, policy_blocked, verification.rejection_reason or "-",
    )

    next_status = CaseStatus.REMEDIATING if verification.verified else CaseStatus.REPORTING
    await update_case(case_id, status=next_status, verification=verification)
    return {"verification": verification, "current_stage": next_status.value}
