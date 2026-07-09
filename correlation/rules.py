"""
Correlation rule framework.

Rules are expressed as two generic primitives so that new attack patterns are
added by *configuration*, not new code:

  ThresholdRule  — N events of a class from the same entity within a window
                   (e.g. brute force = many auth_failure from one source_ip).
  SequenceRule   — event class A then class B from the same entity, in order,
                   within a window (e.g. brute_force_then_login, priv_esc).

Both correlate on a single *entity key* — one of source_ip / user / hostname.
Rules are pure: they receive the current alert's context plus the prior alerts
that already share the relevant entity value, and return a RuleMatch or None.
All storage/query concerns live in the engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from correlation.classifier import (
    AUTH_FAILURE,
    AUTH_SUCCESS,
    PRIV_ESC,
)

# ---------------------------------------------------------------------------
# Data passed between the engine and rules
# ---------------------------------------------------------------------------

@dataclass
class RecentAlert:
    """A prior alert projection pulled from the recent_alerts store."""
    alert_id: str
    event_classes: set[str]
    event_ts: datetime
    source_ip: str = ""
    user: str = ""
    hostname: str = ""


@dataclass
class RuleContext:
    """The current alert's data handed to every rule."""
    alert_id: str
    event_classes: set[str]
    event_ts: datetime
    entities: dict[str, str]  # {"source_ip": .., "user": .., "hostname": ..}


@dataclass
class RuleMatch:
    """The result of a rule that fired."""
    pattern: str
    priority: int
    window_minutes: float
    related_alert_ids: list[str] = field(default_factory=list)
    detail: str = ""


# ---------------------------------------------------------------------------
# Rule primitives
# ---------------------------------------------------------------------------

class CorrelationRule:
    """Base contract. Concrete rules implement evaluate()."""
    name: str
    priority: int
    entity_key: str
    window_minutes: float

    def evaluate(self, ctx: RuleContext, priors: list[RecentAlert]) -> Optional[RuleMatch]:
        raise NotImplementedError


@dataclass
class ThresholdRule(CorrelationRule):
    """
    Fires when the count of `trigger_class` events from the same entity value
    (including the current alert) reaches `threshold` within `window_minutes`.
    """
    name: str
    priority: int
    entity_key: str
    trigger_class: str
    threshold: int
    window_minutes: float

    def evaluate(self, ctx: RuleContext, priors: list[RecentAlert]) -> Optional[RuleMatch]:
        if self.trigger_class not in ctx.event_classes:
            return None

        entity_val = ctx.entities.get(self.entity_key, "")
        if not entity_val:
            return None

        window_start = ctx.event_ts - timedelta(minutes=self.window_minutes)
        matched = [
            p for p in priors
            if self.trigger_class in p.event_classes and p.event_ts >= window_start
        ]

        count = len(matched) + 1  # include the current alert
        if count < self.threshold:
            return None

        detail = (
            f"{self.name}: {count} '{self.trigger_class}' events from "
            f"{self.entity_key}={entity_val} within {self.window_minutes:g}m"
        )
        return RuleMatch(
            pattern=self.name,
            priority=self.priority,
            window_minutes=self.window_minutes,
            related_alert_ids=[p.alert_id for p in matched],
            detail=detail,
        )


@dataclass
class SequenceRule(CorrelationRule):
    """
    Fires when the current alert carries `trigger_class` and at least
    `min_prior_count` `prior_class` events from the same entity value occurred
    within `window_minutes` before it.
    """
    name: str
    priority: int
    entity_key: str
    prior_class: str
    trigger_class: str
    window_minutes: float
    min_prior_count: int = 1

    def evaluate(self, ctx: RuleContext, priors: list[RecentAlert]) -> Optional[RuleMatch]:
        if self.trigger_class not in ctx.event_classes:
            return None

        entity_val = ctx.entities.get(self.entity_key, "")
        if not entity_val:
            return None

        window_start = ctx.event_ts - timedelta(minutes=self.window_minutes)
        prior_hits = [
            p for p in priors
            if self.prior_class in p.event_classes and p.event_ts >= window_start
        ]

        if len(prior_hits) < self.min_prior_count:
            return None

        detail = (
            f"{self.name}: '{self.trigger_class}' preceded by {len(prior_hits)} "
            f"'{self.prior_class}' event(s) from {self.entity_key}={entity_val} "
            f"within {self.window_minutes:g}m"
        )
        return RuleMatch(
            pattern=self.name,
            priority=self.priority,
            window_minutes=self.window_minutes,
            related_alert_ids=[p.alert_id for p in prior_hits],
            detail=detail,
        )


# ---------------------------------------------------------------------------
# Default rule registry
# ---------------------------------------------------------------------------

def build_default_rules(settings) -> list[CorrelationRule]:
    """
    Build the configured rule set from platform settings.

    Adding a new pattern (port scan, FIM tampering burst, recon-then-exploit,
    etc.) is just another entry here — no engine changes required. Priority
    orders which pattern becomes the primary `pattern_matched` when several
    fire on one alert (higher wins); all matches are recorded in `details`.
    """
    return [
        # Brute force: many failed logins from one source IP.
        ThresholdRule(
            name="brute_force",
            priority=10,
            entity_key="source_ip",
            trigger_class=AUTH_FAILURE,
            threshold=settings.brute_force_threshold,
            window_minutes=settings.brute_force_window_minutes,
        ),
        # Brute force then login: a successful login from an IP that just
        # produced a burst of failures. Requires the failure count to reach the
        # brute-force threshold, so a single typo-then-success stays benign.
        SequenceRule(
            name="brute_force_then_login",
            priority=20,
            entity_key="source_ip",
            prior_class=AUTH_FAILURE,
            trigger_class=AUTH_SUCCESS,
            window_minutes=settings.brute_force_then_login_window_minutes,
            min_prior_count=settings.brute_force_threshold,
        ),
        # Privilege escalation after login: a priv-esc event from a user who
        # logged in successfully within the window.
        SequenceRule(
            name="priv_esc_after_login",
            priority=30,
            entity_key="user",
            prior_class=AUTH_SUCCESS,
            trigger_class=PRIV_ESC,
            window_minutes=settings.priv_esc_window_minutes,
            min_prior_count=1,
        ),
    ]
