"""
Enrichment engine.

Runs the three enrichers concurrently and folds their results into a single
EnrichmentContext attached to the alert before it reaches the agentic layer:

  - OTX threat intel on the source IP
  - asset criticality for the target host
  - historical prior-case lookup by IP / user

Each enricher is isolated: a failure or timeout in one (e.g. OTX being down)
does not prevent the others from contributing.
"""

from __future__ import annotations

import asyncio
import logging

from common.models import EnrichmentContext, NormalizedAlert, OTXReputation
from enrichment.asset_context import get_asset_criticality
from enrichment.historical import HistoricalEnricher
from enrichment.otx import OTXEnricher

logger = logging.getLogger("soc.enrichment")


class EnrichmentEngine:
    """Orchestrates threat-intel, asset, and historical enrichment."""

    def __init__(self):
        self.otx = OTXEnricher()
        self.historical = HistoricalEnricher()

    async def initialize(self) -> None:
        """Ensure any indexes/resources the enrichers need are in place."""
        await self.historical.ensure_indexes()

    async def enrich(self, alert: NormalizedAlert) -> EnrichmentContext:
        """Return a fully-populated EnrichmentContext for an alert."""
        otx_result, historical_result = await asyncio.gather(
            self.otx.enrich(alert.source_ip),
            self.historical.enrich(alert),
            return_exceptions=True,
        )

        # --- OTX (isolate failure) ---
        otx_reputation: OTXReputation | None = None
        if isinstance(otx_result, Exception):
            logger.warning("OTX enricher raised: %s", otx_result)
        else:
            otx_reputation = otx_result

        # --- historical (isolate failure) ---
        historical_count = 0
        historical_cases: list = []
        if isinstance(historical_result, Exception):
            logger.warning("Historical enricher raised: %s", historical_result)
        else:
            historical_count, historical_cases = historical_result

        # --- asset criticality (pure/local, no failure path) ---
        asset_criticality = get_asset_criticality(alert.hostname)

        return EnrichmentContext(
            otx_reputation=otx_reputation,
            asset_criticality=asset_criticality,
            historical_case_count=historical_count,
            historical_cases=historical_cases,
        )
