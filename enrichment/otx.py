"""
AlienVault OTX threat-intel enrichment.

Looks up the reputation of a source IP against the OTX DirectConnect API and
returns an OTXReputation.

Caching strategy (matters under live load — the worker processes alerts
sequentially and each OTX call blocks it):
- Successful lookups (including "clean" results with zero pulses) are cached
  for `otx_cache_ttl_seconds` so repeated/correlated alerts for the same IP
  don't re-hit the API.
- Failures (timeout, network error, bad response) are *negative-cached* for
  `otx_failure_cache_ttl_seconds`. Without this, a slow or unreachable OTX
  would cost the full request timeout on every single alert and back the queue
  up. The negative cache bounds that cost to once per IP per short window.

Other behavior:
- Private / reserved IPs are skipped (instant, no API call) — OTX only has
  intelligence on public addresses. Real internet-sourced attacks carry public
  IPs, so this path is exercised in production; internal RFC1918 traffic is
  correctly not looked up.
- Degrades gracefully: no API key, an error, or a timeout all return None
  rather than breaking the pipeline.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from typing import Optional

import httpx

from common.config import settings
from common.database import get_redis_client
from common.models import OTXReputation

logger = logging.getLogger("soc.enrichment.otx")

_CACHE_PREFIX = "otx:ip:"
_FAILURE_MARKER = "__otx_lookup_failed__"
_MAX_TAGS = 10


def _is_public_ip(ip: str) -> bool:
    """True only for routable public IPv4/IPv6 addresses."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


class OTXEnricher:
    """Threat-intel reputation lookups via AlienVault OTX."""

    def __init__(self):
        self.enabled = bool(settings.otx_api_key)
        self.base_url = settings.otx_base_url.rstrip("/")
        self.cache_ttl = settings.otx_cache_ttl_seconds
        self.failure_cache_ttl = settings.otx_failure_cache_ttl_seconds
        # Long read timeout (slow API for popular IPs) but short connect timeout
        # (fail fast on a genuine network/egress problem).
        self.timeout = httpx.Timeout(
            settings.otx_timeout_seconds,
            connect=settings.otx_connect_timeout_seconds,
        )

    async def enrich(self, ip: str) -> Optional[OTXReputation]:
        """Return reputation for a source IP, or None if unavailable/skipped."""
        if not ip or not _is_public_ip(ip):
            return None

        # --- cache lookup (tri-state: hit / negative-hit / absent) ---
        found, cached = await self._get_cached(ip)
        if found:
            # Either a real reputation or a known-recent failure (None). Both
            # short-circuit the API call.
            return cached

        if not self.enabled:
            # No key configured — nothing to look up, and nothing to cache.
            return None

        # --- live API call ---
        reputation = await self._fetch(ip)
        if reputation is not None:
            await self._cache(ip, reputation.model_dump_json(), self.cache_ttl)
        else:
            # Negative-cache the failure so we don't pay the timeout per-alert.
            await self._cache(ip, _FAILURE_MARKER, self.failure_cache_ttl)
        return reputation

    # -- internals ----------------------------------------------------------

    async def _fetch(self, ip: str) -> Optional[OTXReputation]:
        url = f"{self.base_url}/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": settings.otx_api_key}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.warning("OTX lookup failed for %s: %r", ip, exc)
            return None
        except Exception as exc:  # noqa: BLE001 - never let enrichment break the pipeline
            logger.warning("OTX lookup error for %s: %r", ip, exc)
            return None

        return self._parse(data)

    @staticmethod
    def _parse(data: dict) -> OTXReputation:
        pulse_info = data.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count") or 0)

        # Aggregate a deduplicated set of tags from the associated pulses.
        tags: list[str] = []
        seen: set[str] = set()
        for pulse in (pulse_info.get("pulses") or []):
            for tag in (pulse.get("tags") or []):
                t = str(tag)
                if t and t not in seen:
                    seen.add(t)
                    tags.append(t)
                    if len(tags) >= _MAX_TAGS:
                        break
            if len(tags) >= _MAX_TAGS:
                break

        # OTX 'reputation' is often 0/null on the general endpoint; fall back to
        # pulse count as a coarse score so downstream has something to weight.
        raw_reputation = data.get("reputation")
        reputation_score = raw_reputation if isinstance(raw_reputation, int) else pulse_count

        country = str(data.get("country_name") or data.get("country_code") or "")

        return OTXReputation(
            is_known_malicious=pulse_count > 0,
            pulse_count=pulse_count,
            reputation_score=reputation_score,
            tags=tags,
            country=country,
        )

    async def _get_cached(self, ip: str) -> tuple[bool, Optional[OTXReputation]]:
        """
        Return (found, reputation).

        found=False  -> nothing cached, caller should hit the API
        found=True, reputation=None      -> negative-cached failure
        found=True, reputation=OTXReputation -> cached result
        """
        try:
            redis = await get_redis_client()
            raw = await redis.get(f"{_CACHE_PREFIX}{ip}")
            if raw is None:
                return False, None
            if raw == _FAILURE_MARKER:
                return True, None
            return True, OTXReputation(**json.loads(raw))
        except Exception as exc:  # noqa: BLE001
            logger.debug("OTX cache read failed for %s: %s", ip, exc)
            return False, None

    async def _cache(self, ip: str, value: str, ttl: int) -> None:
        try:
            redis = await get_redis_client()
            await redis.set(f"{_CACHE_PREFIX}{ip}", value, ex=ttl)
        except Exception as exc:  # noqa: BLE001
            logger.debug("OTX cache write failed for %s: %s", ip, exc)
