"""
Pipeline worker — the main processing loop.

Reads alerts from Redis (BRPOP), processes them through the pipeline,
and writes results to MongoDB. In Phase 0 this is a simple pass-through;
later phases add correlation, enrichment, and the agentic layer.
"""

import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timezone

from common.config import settings
from common.database import (
    get_mongo_db,
    get_redis_client,
    close_mongo,
    close_redis,
)
from common.models import NormalizedAlert, CaseDocument, CaseStatus
from correlation.engine import CorrelationEngine

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("soc.worker")

# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------

_shutdown_event = asyncio.Event()

# ---------------------------------------------------------------------------
# Pipeline stages (shared across the worker)
# ---------------------------------------------------------------------------

correlation_engine = CorrelationEngine()


def _handle_signal(sig, frame):
    logger.info("Received signal %s — shutting down gracefully", sig)
    _shutdown_event.set()


# ---------------------------------------------------------------------------
# Pipeline processing (Phase 2: correlation)
# ---------------------------------------------------------------------------

async def process_alert(alert: NormalizedAlert) -> None:
    """
    Process a single alert through the pipeline.

    Phase 2: Runs correlation and attaches a CorrelationContext to the case.
    Later phases will add: enrichment → agent pipeline.
    """
    db = get_mongo_db()

    # --- Correlation ---
    correlation = await correlation_engine.correlate(alert)

    # Create a case document for this alert
    case = CaseDocument(
        alert=alert,
        correlation=correlation,
        status=CaseStatus.CORRELATING,  # furthest stage reached so far
    )

    # Write to MongoDB
    await db.cases.insert_one(case.model_dump(mode="json"))
    logger.info(
        "Case %s | alert %s | rule='%s' level=%d | pattern=%s related=%d",
        case.case_id,
        alert.alert_id,
        alert.rule_description,
        alert.rule_level,
        correlation.pattern_matched or "none",
        correlation.related_alert_count,
    )


# ---------------------------------------------------------------------------
# Main worker loop
# ---------------------------------------------------------------------------

async def worker_loop():
    """
    Main loop: BRPOP from Redis, deserialize, process.

    Uses BRPOP with a 1-second timeout so the loop can check
    the shutdown event regularly.
    """
    redis = await get_redis_client()
    db = get_mongo_db()

    logger.info(
        "Worker started — listening on Redis queue '%s'",
        settings.redis_queue_key,
    )

    while not _shutdown_event.is_set():
        try:
            # BRPOP blocks until an item is available (with timeout)
            result = await redis.brpop(
                settings.redis_queue_key,
                timeout=int(settings.worker_poll_interval),
            )

            if result is None:
                # Timeout — no items in queue, loop back
                continue

            _queue_name, raw_payload = result
            logger.info("Received alert from Redis queue")

            try:
                alert_data = json.loads(raw_payload)
                alert = NormalizedAlert(**alert_data)
            except (json.JSONDecodeError, Exception) as parse_err:
                # Failed to parse — send to DLQ
                logger.error("Failed to parse alert: %s", parse_err)
                dlq_entry = json.dumps({
                    "raw_payload": raw_payload,
                    "error": str(parse_err),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                await redis.lpush(settings.redis_dlq_key, dlq_entry)
                logger.warning("Alert sent to DLQ: %s", settings.redis_dlq_key)
                continue

            # Process through the pipeline
            await process_alert(alert)

        except asyncio.CancelledError:
            logger.info("Worker loop cancelled")
            break
        except Exception as exc:
            logger.exception("Unexpected error in worker loop: %s", exc)
            await asyncio.sleep(2)  # Back off on unexpected errors


async def main():
    """Entry point for the worker service."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logger.info("Starting SOC Pipeline Worker...")

    try:
        await correlation_engine.initialize()
        await worker_loop()
    finally:
        logger.info("Cleaning up connections...")
        await close_redis()
        await close_mongo()
        logger.info("Worker shut down cleanly")


if __name__ == "__main__":
    asyncio.run(main())
