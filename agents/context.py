"""
Human-readable formatting of an EnrichedAlert for LLM prompts.

Centralized so every agent describes the same alert the same way. Kept compact
and factual — no interpretation (that's the agents' job).
"""

from __future__ import annotations

from common.models import EnrichedAlert


def describe_enriched(enriched: EnrichedAlert) -> str:
    """Render the alert + correlation + enrichment as a compact prompt block."""
    a = enriched.alert
    c = enriched.correlation
    e = enriched.enrichment

    lines = [
        "## Alert",
        f"- rule: {a.rule_description} (id={a.rule_id}, level={a.rule_level})",
        f"- source_ip: {a.source_ip or 'n/a'}  dest_ip: {a.dest_ip or 'n/a'}",
        f"- user: {a.user or 'n/a'}  hostname: {a.hostname or 'n/a'}",
        f"- groups: {', '.join(a.rule_groups) or 'n/a'}",
        f"- timestamp: {a.timestamp.isoformat()}",
        "",
        "## Correlation",
        f"- pattern_matched: {c.pattern_matched or 'none'}",
        f"- related_alert_count: {c.related_alert_count}",
        f"- time_window_minutes: {c.time_window_minutes}",
        f"- details: {c.details or 'n/a'}",
        "",
        "## Enrichment",
        f"- asset_criticality: {e.asset_criticality}",
        f"- historical_case_count: {e.historical_case_count}",
    ]

    if e.otx_reputation is not None:
        r = e.otx_reputation
        lines.append(
            f"- otx: {'KNOWN MALICIOUS' if r.is_known_malicious else 'clean'} "
            f"(pulses={r.pulse_count}, score={r.reputation_score}, "
            f"tags={', '.join(r.tags) or 'none'})"
        )
    else:
        lines.append("- otx: no threat-intel data (private IP or lookup unavailable)")

    return "\n".join(lines)
