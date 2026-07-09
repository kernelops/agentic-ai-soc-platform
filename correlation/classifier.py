"""
Deterministic event classification for the correlation engine.

Maps a NormalizedAlert onto one or more *semantic event classes* so that
correlation rules never have to hardcode Wazuh rule IDs. The same rule then
works across decoders and attack tools (e.g. any failed SSH login classifies
as `auth_failure`, whether it comes from Hydra, a manual attempt, or a
different sshd decoder).

Classification is rule-based and deterministic — no ML, no scoring. It reads,
in priority order:
  1. Wazuh `rule.groups`      (strongest, most stable signal)
  2. the rule description     (keyword fallback)
  3. the MITRE tactic         (fallback, from the raw payload)
"""

from __future__ import annotations

from typing import Any

from common.models import NormalizedAlert

# ---------------------------------------------------------------------------
# Event classes (the vocabulary correlation rules operate on)
# ---------------------------------------------------------------------------

AUTH_FAILURE = "auth_failure"
AUTH_SUCCESS = "auth_success"
PRIV_ESC = "priv_esc"
FILE_INTEGRITY = "file_integrity"
NETWORK_RECON = "network_recon"

# ---------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------

# Wazuh rule.groups -> event class. Groups are lowercased before lookup.
_GROUP_MAP: dict[str, str] = {
    "authentication_failed": AUTH_FAILURE,
    "authentication_failures": AUTH_FAILURE,
    "win_authentication_failed": AUTH_FAILURE,
    "invalid_login": AUTH_FAILURE,
    "authentication_success": AUTH_SUCCESS,
    "win_authentication_success": AUTH_SUCCESS,
    "privilege_escalation": PRIV_ESC,
    "syscheck": FILE_INTEGRITY,
    "syscheck_file": FILE_INTEGRITY,
    "syscheck_entry_modified": FILE_INTEGRITY,
    "syscheck_entry_added": FILE_INTEGRITY,
    "syscheck_entry_deleted": FILE_INTEGRITY,
    "recon": NETWORK_RECON,
    "nmap": NETWORK_RECON,
    "portscan": NETWORK_RECON,
    "web_scan": NETWORK_RECON,
}

# MITRE tactic -> event class (fallback only). Kept deliberately narrow to the
# tactics that map cleanly; auth success/failure is better distinguished via
# groups/description than via tactic.
_MITRE_TACTIC_MAP: dict[str, str] = {
    "privilege escalation": PRIV_ESC,
    "discovery": NETWORK_RECON,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify(alert: NormalizedAlert) -> set[str]:
    """
    Return the set of semantic event classes for an alert.

    An alert can carry more than one class. Returns an empty set for alerts we
    can't classify — correlation still attaches ambient context in that case.
    """
    classes: set[str] = set()

    for group in alert.rule_groups:
        mapped = _GROUP_MAP.get(str(group).lower())
        if mapped:
            classes.add(mapped)

    if not classes:
        classes |= _classify_by_description(alert.rule_description)

    if not classes:
        classes |= _classify_by_mitre(alert.raw_payload)

    return classes


# ---------------------------------------------------------------------------
# Fallback classifiers
# ---------------------------------------------------------------------------

def _classify_by_description(description: str) -> set[str]:
    """Keyword-based fallback when rule groups yield nothing."""
    desc = (description or "").lower()
    out: set[str] = set()

    if any(k in desc for k in (
        "authentication failed", "authentication failure",
        "failed password", "invalid user", "login failed",
    )):
        out.add(AUTH_FAILURE)
    if any(k in desc for k in (
        "authentication success", "accepted password",
        "session opened", "logged in",
    )):
        out.add(AUTH_SUCCESS)
    if any(k in desc for k in ("sudo", "privilege", "escalation")):
        out.add(PRIV_ESC)
    if any(k in desc for k in ("integrity", "checksum", "file modified")):
        out.add(FILE_INTEGRITY)
    if any(k in desc for k in ("scan", "recon", "nmap", "port sweep")):
        out.add(NETWORK_RECON)

    return out


def _classify_by_mitre(raw_payload: Any) -> set[str]:
    """Fallback using the MITRE tactic recorded in the raw Wazuh payload."""
    out: set[str] = set()
    if not isinstance(raw_payload, dict):
        return out

    rule = raw_payload.get("rule")
    mitre = rule.get("mitre") if isinstance(rule, dict) else None
    tactics = mitre.get("tactic") if isinstance(mitre, dict) else None
    if not isinstance(tactics, list):
        return out

    for tactic in tactics:
        mapped = _MITRE_TACTIC_MAP.get(str(tactic).lower())
        if mapped:
            out.add(mapped)

    return out
