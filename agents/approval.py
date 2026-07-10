"""
Approval gate — not an LLM call, a policy checkpoint.

If any proposed remediation action is destructive (block/disable/isolate), the
case is marked PENDING_APPROVAL and an approval record is written to Mongo — a
human must approve before anything executes. If all proposed actions are
non-destructive, they are auto-approved and the case proceeds.

The gate never blocks the graph: it records the pending state and lets the case
flow to reporting so every alert finalizes with a documented trail. A real
approve/reject action (Slack webhook / UI, Phase 6) flips the Mongo flag
out-of-band later.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from agents.persistence import update_case
from agents.state import PipelineState
from common.models import CaseStatus

logger = logging.getLogger("soc.agents.approval")


async def approval_node(state: PipelineState) -> dict:
    case_id = state["case_id"]
    remediation = state.get("remediation")
    actions = remediation.proposed_actions if remediation else []
    has_destructive = any(a.is_destructive for a in actions)

    now = datetime.now(timezone.utc).isoformat()
    if has_destructive:
        approval = {"required": True, "status": "pending", "requested_at": now}
        status = CaseStatus.PENDING_APPROVAL
        approval_status = "pending"
        # TODO(Phase 6): notify_slack(case_id, remediation) for the approval request.
        logger.info("Approval case %s | destructive actions -> PENDING_APPROVAL", case_id)
    else:
        approval = {"required": False, "status": "auto_approved", "decided_at": now}
        status = CaseStatus.REPORTING
        approval_status = "auto_approved"
        logger.info("Approval case %s | non-destructive -> auto-approved", case_id)

    await update_case(case_id, status=status, approval=approval)
    return {"approval_status": approval_status, "current_stage": status.value}
