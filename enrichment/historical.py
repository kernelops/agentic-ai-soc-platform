"""
Historical context enrichment.

Looks up prior cases in MongoDB involving the same source IP or user, giving
downstream agents a baseline ("this IP has 12 prior flagged cases" vs. "this
user has never triggered an alert before").

Scope is all-time for the demo. Because every alert creates a case, alerts
within the same ongoing incident can appear as each other's history — that's
intentional (prior related activity is signal), and downstream agents see the
correlation context alongside it.
"""

from __future__ import annotations

import logging
from typing import Any

from common.database import get_mongo_db
from common.models import NormalizedAlert

logger = logging.getLogger("soc.enrichment.historical")

_SUMMARY_LIMIT = 5  # most-recent prior cases to summarize


class HistoricalEnricher:
    """Queries the cases collection for prior activity by IP or user."""

    async def ensure_indexes(self) -> None:
        """
        Create the indexes the historical lookup relies on.

        Without these, every enrichment does a collection scan of `cases`,
        which degrades as case volume grows in a live deployment.
        """
        db = get_mongo_db()
        await db.cases.create_index("alert.source_ip")
        await db.cases.create_index("alert.user")
        await db.cases.create_index("created_at")
        logger.info("Historical enrichment indexes ensured on 'cases'")

    async def enrich(self, alert: NormalizedAlert) -> tuple[int, list[dict[str, Any]]]:
        """Return (total_prior_case_count, recent_case_summaries)."""
        conditions: list[dict[str, Any]] = []
        if alert.source_ip:
            conditions.append({"alert.source_ip": alert.source_ip})
        if alert.user:
            conditions.append({"alert.user": alert.user})

        if not conditions:
            return 0, []

        query = {"$or": conditions} if len(conditions) > 1 else conditions[0]

        try:
            db = get_mongo_db()
            count = await db.cases.count_documents(query)

            summaries: list[dict[str, Any]] = []
            cursor = (
                db.cases.find(
                    query,
                    {
                        "_id": 0,
                        "case_id": 1,
                        "status": 1,
                        "created_at": 1,
                        "alert.rule_description": 1,
                        "alert.source_ip": 1,
                        "alert.user": 1,
                        "correlation.pattern_matched": 1,
                    },
                )
                .sort("created_at", -1)
                .limit(_SUMMARY_LIMIT)
            )
            async for doc in cursor:
                alert_doc = doc.get("alert") or {}
                correlation_doc = doc.get("correlation") or {}
                summaries.append({
                    "case_id": doc.get("case_id", ""),
                    "status": doc.get("status", ""),
                    "created_at": doc.get("created_at", ""),
                    "rule_description": alert_doc.get("rule_description", ""),
                    "source_ip": alert_doc.get("source_ip", ""),
                    "user": alert_doc.get("user", ""),
                    "pattern_matched": correlation_doc.get("pattern_matched", ""),
                })

            return count, summaries
        except Exception as exc:  # noqa: BLE001 - never let enrichment break the pipeline
            logger.warning("Historical lookup failed: %s", exc)
            return 0, []
