"""
Correlation engine.

Owns the `recent_alerts` store and orchestrates the rule registry. For each
incoming alert it:
  1. classifies the alert into semantic event classes
  2. fetches prior alerts sharing its entities (query happens *before* insert,
     so an alert never correlates with itself)
  3. evaluates every registered rule, collecting all matches
  4. computes ambient correlation (recent alerts sharing IP/user/host)
  5. stores the alert so it becomes history for the next one
  6. returns a CorrelationContext

Dual-clock timestamps: window comparisons use the alert's *event time*
(`alert.timestamp`), while the TTL that expires the store uses *ingestion
time*. This lets replayed fixtures (with static event times) correlate while
still being reaped, and keeps the live demo correct where both clocks agree.
All datetimes are normalized to naive UTC internally to avoid aware/naive
comparison errors against values returned by MongoDB.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from common.config import settings
from common.database import get_mongo_db
from common.models import CorrelationContext, NormalizedAlert
from correlation.classifier import classify
from correlation.rules import (
    CorrelationRule,
    RecentAlert,
    RuleContext,
    RuleMatch,
    build_default_rules,
)

logger = logging.getLogger("soc.correlation")

RECENT_ALERTS_COLLECTION = "recent_alerts"
ENTITY_KEYS = ("source_ip", "user", "hostname")


def _to_utc_naive(dt: datetime) -> datetime:
    """Normalize any datetime to naive UTC for consistent comparisons/storage."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class CorrelationEngine:
    """Rule-based correlation over a rolling window of recent alerts."""

    def __init__(self, rules: list[CorrelationRule] | None = None):
        self.rules = rules if rules is not None else build_default_rules(settings)
        self.lookback_minutes = settings.correlation_window_minutes
        self.retention_seconds = settings.recent_alerts_retention_minutes * 60

    @property
    def _collection(self):
        return get_mongo_db()[RECENT_ALERTS_COLLECTION]

    async def initialize(self) -> None:
        """Create the TTL and supporting indexes (idempotent)."""
        col = self._collection
        # TTL: expire entries `retention_seconds` after ingestion time.
        await col.create_index("ingested_at", expireAfterSeconds=self.retention_seconds)
        # Supporting indexes for the per-entity prior lookups.
        await col.create_index([("source_ip", 1), ("event_ts", 1)])
        await col.create_index([("user", 1), ("event_ts", 1)])
        await col.create_index([("hostname", 1), ("event_ts", 1)])
        logger.info(
            "Correlation store initialized (retention=%ds, lookback=%dm, rules=%d)",
            self.retention_seconds,
            self.lookback_minutes,
            len(self.rules),
        )

    async def correlate(self, alert: NormalizedAlert) -> CorrelationContext:
        """Correlate a single alert and return its CorrelationContext."""
        event_classes = classify(alert)
        event_ts = _to_utc_naive(alert.timestamp)
        entities = {key: (getattr(alert, key, "") or "") for key in ENTITY_KEYS}

        priors_by_key = await self._fetch_priors(entities, event_ts)

        ctx = RuleContext(
            alert_id=alert.alert_id,
            event_classes=event_classes,
            event_ts=event_ts,
            entities=entities,
        )

        matches: list[RuleMatch] = []
        for rule in self.rules:
            priors = priors_by_key.get(rule.entity_key, [])
            match = rule.evaluate(ctx, priors)
            if match:
                matches.append(match)

        # Ambient correlation: every recent alert sharing any entity value.
        ambient_ids = sorted({
            prior.alert_id
            for priors in priors_by_key.values()
            for prior in priors
        })

        # Store *after* querying so the alert becomes history for the next one.
        await self._store(alert, event_classes, event_ts, entities)

        return self._build_context(matches, ambient_ids)

    # -- store helpers ------------------------------------------------------

    async def _fetch_priors(
        self, entities: dict[str, str], event_ts: datetime
    ) -> dict[str, list[RecentAlert]]:
        """Fetch prior alerts within the broad lookback window, per entity key."""
        window_start = event_ts - timedelta(minutes=self.lookback_minutes)
        out: dict[str, list[RecentAlert]] = {}

        for key in ENTITY_KEYS:
            value = entities.get(key, "")
            if not value:
                continue  # never correlate on an empty entity value

            cursor = self._collection.find({
                key: value,
                "event_ts": {"$gte": window_start, "$lte": event_ts},
            })

            priors: list[RecentAlert] = []
            async for doc in cursor:
                priors.append(RecentAlert(
                    alert_id=doc.get("alert_id", ""),
                    event_classes=set(doc.get("event_classes", [])),
                    event_ts=doc.get("event_ts"),
                    source_ip=doc.get("source_ip", ""),
                    user=doc.get("user", ""),
                    hostname=doc.get("hostname", ""),
                ))
            out[key] = priors

        return out

    async def _store(
        self,
        alert: NormalizedAlert,
        event_classes: set[str],
        event_ts: datetime,
        entities: dict[str, str],
    ) -> None:
        """Persist a lightweight projection of the alert into the rolling store."""
        doc = {
            "alert_id": alert.alert_id,
            "source_ip": entities["source_ip"],
            "user": entities["user"],
            "hostname": entities["hostname"],
            "event_classes": sorted(event_classes),
            "rule_id": alert.rule_id,
            "rule_level": alert.rule_level,
            "rule_description": alert.rule_description,
            "event_ts": event_ts,          # for window comparisons
            "ingested_at": _utcnow_naive(),  # for TTL expiry
        }
        await self._collection.insert_one(doc)

    # -- output -------------------------------------------------------------

    def _build_context(
        self, matches: list[RuleMatch], ambient_ids: list[str]
    ) -> CorrelationContext:
        """Fold rule matches + ambient context into a CorrelationContext."""
        if matches:
            matches.sort(key=lambda m: m.priority, reverse=True)
            primary = matches[0]
            details = "; ".join(m.detail for m in matches)
            return CorrelationContext(
                related_alert_count=len(ambient_ids),
                pattern_matched=primary.pattern,
                time_window_minutes=primary.window_minutes,
                related_alert_ids=ambient_ids,
                details=details,
            )

        details = (
            f"No correlation pattern matched; {len(ambient_ids)} related recent "
            f"alert(s) share IP/user/host."
            if ambient_ids
            else "No correlation pattern matched; no related recent alerts."
        )
        return CorrelationContext(
            related_alert_count=len(ambient_ids),
            pattern_matched="",
            time_window_minutes=0.0,
            related_alert_ids=ambient_ids,
            details=details,
        )
