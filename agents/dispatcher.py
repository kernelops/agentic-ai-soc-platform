"""
Dispatcher node — intake, no LLM.

The worker has already created the case document (so historical enrichment of
later alerts can see it). The dispatcher's job is purely to open the agentic
pipeline: mark the case as entering triage. Kept as its own node so the graph
mirrors a real SOC intake desk and gives us a clean place to add per-case setup
later (e.g. SLA timers, dedupe).
"""

from __future__ import annotations

import logging

from agents.persistence import update_case
from agents.state import PipelineState
from common.models import CaseStatus

logger = logging.getLogger("soc.agents.dispatcher")


async def dispatcher_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    alert = state["enriched"].alert
    logger.info("Dispatch case %s | rule='%s' level=%d", case_id, alert.rule_description, alert.rule_level)
    await update_case(case_id, status=CaseStatus.TRIAGING)
    return {"current_stage": CaseStatus.TRIAGING.value}
