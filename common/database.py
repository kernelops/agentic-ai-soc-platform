"""
Database connection helpers for MongoDB (Motor) and Redis (aioredis).

Provides async clients with connection pooling and health checks.
Both clients are initialized lazily and shared across the application.
"""

import logging
from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from redis.asyncio import Redis, from_url as redis_from_url

from common.config import settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------

_mongo_client: Optional[AsyncIOMotorClient] = None


def get_mongo_client() -> AsyncIOMotorClient:
    """Get or create the shared MongoDB client."""
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = AsyncIOMotorClient(settings.mongo_url)
        logger.info("MongoDB client created: %s", settings.mongo_url)
    return _mongo_client


def get_mongo_db() -> AsyncIOMotorDatabase:
    """Get the platform's MongoDB database."""
    return get_mongo_client()[settings.mongo_db_name]


async def close_mongo():
    """Close the MongoDB client connection."""
    global _mongo_client
    if _mongo_client is not None:
        _mongo_client.close()
        _mongo_client = None
        logger.info("MongoDB client closed")


async def check_mongo_health() -> bool:
    """Ping MongoDB to verify connectivity."""
    try:
        await get_mongo_client().admin.command("ping")
        return True
    except Exception as exc:
        logger.error("MongoDB health check failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------

_redis_client: Optional[Redis] = None


async def get_redis_client() -> Redis:
    """Get or create the shared async Redis client."""
    global _redis_client
    if _redis_client is None:
        _redis_client = redis_from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=20,
        )
        logger.info("Redis client created: %s", settings.redis_url)
    return _redis_client


async def close_redis():
    """Close the Redis client connection."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None
        logger.info("Redis client closed")


async def check_redis_health() -> bool:
    """Ping Redis to verify connectivity."""
    try:
        client = await get_redis_client()
        return await client.ping()
    except Exception as exc:
        logger.error("Redis health check failed: %s", exc)
        return False
