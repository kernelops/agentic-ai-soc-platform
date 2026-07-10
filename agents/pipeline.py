"""
LangGraph pipeline assembly + entrypoint.

Wires the agent nodes into the sequential SOC pipeline with conditional routing:

    START -> dispatcher -> triage -> investigation -> [verdict_router]
      false_positive / unverified -> reporting
      true_positive               -> verification -> [verified_router]
        verified -> remediation -> approval -> reporting
        rejected -> reporting
    reporting -> END

The compiled graph is built once and reused. `run_pipeline` seeds the state with
the enriched alert + case_id and drives it with `ainvoke` (async — the worker
loop is asyncio and must never be blocked by a sync graph call).
"""

from __future__ import annotations

import logging

from langgraph.graph import END, START, StateGraph

from agents.approval import approval_node
from agents.dispatcher import dispatcher_node
from agents.investigation import investigation_node
from agents.remediation import remediation_node
from agents.reporting import reporting_node
from agents.state import PipelineState
from agents.triage import triage_node
from agents.verification import verification_node
from common.models import EnrichedAlert, Verdict

logger = logging.getLogger("soc.agents.pipeline")

_compiled = None  # module-level singleton


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------

def verdict_router(state: PipelineState) -> str:
    """True positives go to verification; anything else reports out directly."""
    investigation = state.get("investigation")
    if investigation is not None and investigation.verdict == Verdict.TRUE_POSITIVE:
        return "verify"
    return "finalize"


def verified_router(state: PipelineState) -> str:
    """Verified conclusions proceed to remediation; rejections report out."""
    verification = state.get("verification")
    if verification is not None and verification.verified:
        return "remediate"
    return "finalize"


# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

def build_pipeline():
    """Build and compile the StateGraph once; return the cached compiled graph."""
    global _compiled
    if _compiled is not None:
        return _compiled

    # Node ids are distinct verbs so none collide with PipelineState keys
    # (LangGraph forbids a node id that equals a state key).
    g = StateGraph(PipelineState)
    g.add_node("dispatch", dispatcher_node)
    g.add_node("classify", triage_node)
    g.add_node("investigate", investigation_node)
    g.add_node("verify", verification_node)
    g.add_node("remediate", remediation_node)
    g.add_node("approve", approval_node)
    g.add_node("finalize", reporting_node)

    g.add_edge(START, "dispatch")
    g.add_edge("dispatch", "classify")
    g.add_edge("classify", "investigate")
    g.add_conditional_edges(
        "investigate", verdict_router,
        {"verify": "verify", "finalize": "finalize"},
    )
    g.add_conditional_edges(
        "verify", verified_router,
        {"remediate": "remediate", "finalize": "finalize"},
    )
    g.add_edge("remediate", "approve")
    g.add_edge("approve", "finalize")
    g.add_edge("finalize", END)

    _compiled = g.compile()
    logger.info("Agent pipeline compiled")
    return _compiled


async def run_pipeline(enriched: EnrichedAlert, case_id: str) -> PipelineState:
    """Run one enriched alert through the full agent pipeline."""
    graph = build_pipeline()
    initial: PipelineState = {"case_id": case_id, "enriched": enriched}
    return await graph.ainvoke(initial)
