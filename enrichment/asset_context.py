"""
Asset context enrichment.

Maps a hostname to an asset-criticality level so downstream agents can weight
severity by how important the affected host is (a brute force against
`prod-db-01` matters more than against `dev-vm-03`).

For the demo this is a static mapping driven by config. In production this
slot would query a CMDB / asset inventory instead — the interface stays the
same.
"""

from __future__ import annotations

from common.config import settings

# Recognized criticality levels, ordered low -> high for reference.
CRITICALITY_LEVELS = ("low", "medium", "high", "critical")
UNKNOWN = "unknown"


def get_asset_criticality(hostname: str) -> str:
    """
    Return the criticality for a hostname, or "unknown" if not mapped.

    Lookup is case-insensitive on the hostname.
    """
    if not hostname:
        return UNKNOWN

    # Build a case-insensitive view of the configured map.
    host = hostname.strip().lower()
    for mapped_host, level in settings.asset_criticality_map.items():
        if mapped_host.strip().lower() == host:
            return level if level in CRITICALITY_LEVELS else UNKNOWN

    return UNKNOWN
