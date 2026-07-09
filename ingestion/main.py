"""
FastAPI Ingestion Service for the Agentic AI SOC Platform.

Receives Wazuh webhook alerts, validates auth, normalizes the payload
into the internal schema, and pushes to Redis. Malformed alerts go
to the Dead Letter Queue.
"""

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Header
from pydantic import BaseModel

from common.config import settings
from common.database import (
    get_redis_client,
    close_redis,
    close_mongo,
    check_redis_health,
    check_mongo_health,
)
from common.models import WazuhAlert, NormalizedAlert

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("soc.ingestion")

# ---------------------------------------------------------------------------
# Metrics (simple counters — Prometheus integration added in Phase 6)
# ---------------------------------------------------------------------------

metrics = {
    "alerts_received": 0,
    "alerts_parsed": 0,
    "alerts_dlq": 0,
}

# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage Redis and MongoDB connections on startup/shutdown."""
    logger.info("Ingestion service starting up...")
    # Eagerly initialize connections to fail fast
    await get_redis_client()
    logger.info("Redis connected")
    yield
    logger.info("Ingestion service shutting down...")
    await close_redis()
    await close_mongo()
    logger.info("Connections closed")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SOC Platform — Ingestion Service",
    description="Receives Wazuh security alerts and queues them for the agentic pipeline.",
    version="0.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_wazuh_alert(wazuh: WazuhAlert) -> NormalizedAlert:
    """
    Convert a raw Wazuh alert into our internal normalized schema.

    Extracts source IP, user, hostname etc. from the nested Wazuh structure.
    """
    return NormalizedAlert(
        timestamp=_parse_wazuh_timestamp(wazuh.timestamp),
        source_ip=wazuh.data.get("srcip", ""),
        dest_ip=wazuh.data.get("dstip", wazuh.agent.ip),
        user=wazuh.data.get("dstuser", wazuh.data.get("srcuser", "")),
        hostname=wazuh.agent.name,
        rule_id=wazuh.rule.id,
        rule_level=wazuh.rule.level,
        rule_description=wazuh.rule.description,
        rule_groups=wazuh.rule.groups,
        location=wazuh.location,
        full_log=wazuh.full_log,
        raw_payload=wazuh.model_dump(),
    )


def _parse_wazuh_timestamp(ts: str) -> datetime:
    """Parse Wazuh timestamp, falling back to now() if unparseable."""
    if not ts:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str
    redis: bool
    mongodb: bool


@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Health check — verifies Redis and MongoDB connectivity."""
    redis_ok = await check_redis_health()
    mongo_ok = await check_mongo_health()
    status = "healthy" if (redis_ok and mongo_ok) else "degraded"
    return HealthResponse(status=status, redis=redis_ok, mongodb=mongo_ok)


@app.get("/api/v1/metrics")
async def get_metrics():
    """Simple metrics endpoint (replaced by Prometheus in Phase 6)."""
    redis = await get_redis_client()
    queue_depth = await redis.llen(settings.redis_queue_key)
    dlq_depth = await redis.llen(settings.redis_dlq_key)
    return {
        **metrics,
        "queue_depth": queue_depth,
        "dlq_depth": dlq_depth,
    }


@app.post("/api/v1/alerts/wazuh", status_code=202)
async def receive_wazuh_alert(
    request: Request,
    authorization: str = Header(default=""),
):
    """
    Receive a Wazuh webhook alert.

    - Validates the auth token
    - Parses and normalizes the Wazuh JSON
    - Pushes to Redis queue
    - On parse failure → pushes to DLQ
    """
    # --- Auth check ---
    expected = f"Bearer {settings.ingestion_auth_token}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="Invalid or missing auth token")

    metrics["alerts_received"] += 1
    redis = await get_redis_client()

    # --- Parse the raw body ---
    try:
        body = await request.json()
    except Exception as exc:
        logger.error("Failed to read request body: %s", exc)
        metrics["alerts_dlq"] += 1
        await redis.lpush(
            settings.redis_dlq_key,
            json.dumps({
                "error": f"Invalid JSON body: {exc}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }),
        )
        return {"status": "error", "detail": "Invalid JSON", "queue": "dlq"}

    # --- Normalize ---
    try:
        wazuh_alert = WazuhAlert(**body)
        normalized = normalize_wazuh_alert(wazuh_alert)
    except Exception as exc:
        logger.error("Failed to normalize Wazuh alert: %s", exc)
        metrics["alerts_dlq"] += 1
        await redis.lpush(
            settings.redis_dlq_key,
            json.dumps({
                "raw_payload": body,
                "error": f"Normalization failed: {exc}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }),
        )
        return {"status": "error", "detail": "Normalization failed", "queue": "dlq"}

    # --- Push to Redis queue ---
    alert_json = normalized.model_dump_json()
    await redis.lpush(settings.redis_queue_key, alert_json)
    metrics["alerts_parsed"] += 1

    logger.info(
        "Alert ingested: id=%s src_ip=%s rule='%s' level=%d",
        normalized.alert_id,
        normalized.source_ip,
        normalized.rule_description,
        normalized.rule_level,
    )

    return {
        "status": "accepted",
        "alert_id": normalized.alert_id,
        "queue": settings.redis_queue_key,
    }
