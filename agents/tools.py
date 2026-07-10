"""
Investigation tools + RAG stubs.

Two kinds of tool live here:

1. Evidence tools (`get_login_history`, `check_user_baseline`,
   `get_correlation_context`) — read the `recent_alerts` / `cases` collections
   and the already-attached correlation context. The Investigation agent calls
   these directly as ordinary async functions (a prescribed sequence, not an
   LLM tool-calling loop) and hands the results to a single structured-output
   synthesis call.

2. RAG stubs (`query_mitre_attack`, `query_runbooks`) — return hardcoded MITRE
   ATT&CK / runbook data for now. Their signatures mirror what a future ChromaDB
   `RAGStore.query(collection, text, n_results)` will provide, so Phase 4 swaps
   the body without touching any caller.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from common.config import settings
from common.database import get_mongo_db
from common.models import CorrelationContext

logger = logging.getLogger("soc.agents.tools")

RECENT_ALERTS_COLLECTION = "recent_alerts"

# Event-class labels as written by the correlation classifier.
_AUTH_FAILURE = "auth_failure"
_AUTH_SUCCESS = "auth_success"


def _to_utc_naive(dt: datetime) -> datetime:
    """Normalize any datetime to naive UTC (recent_alerts stores naive UTC)."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ---------------------------------------------------------------------------
# Evidence tools (Mongo / state reads)
# ---------------------------------------------------------------------------

async def get_login_history(
    user: str,
    source_ip: str,
    reference_ts: datetime | None = None,
    window_minutes: int | None = None,
) -> dict[str, Any]:
    """
    Summarize recent login activity for a user or source IP.

    Queries `recent_alerts` for events sharing the user or source IP within the
    lookback window ending at `reference_ts` (the current alert's event time, so
    replayed fixtures and live alerts behave identically). Failure/success counts
    are derived from the correlation classifier's `event_classes`.
    """
    if not user and not source_ip:
        return {"failed_logins": 0, "successful_logins": 0, "events": [], "note": "no user/ip"}

    window = window_minutes if window_minutes is not None else settings.correlation_window_minutes
    ref = _to_utc_naive(reference_ts or datetime.now(timezone.utc))
    window_start = ref - timedelta(minutes=window)

    entity_clause: list[dict[str, Any]] = []
    if source_ip:
        entity_clause.append({"source_ip": source_ip})
    if user:
        entity_clause.append({"user": user})

    query = {
        "$and": [
            {"$or": entity_clause},
            {"event_ts": {"$gte": window_start, "$lte": ref}},
        ]
    }

    failed = success = 0
    events: list[dict[str, Any]] = []
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    try:
        db = get_mongo_db()
        cursor = db[RECENT_ALERTS_COLLECTION].find(
            query,
            {
                "_id": 0, "alert_id": 1, "event_classes": 1, "event_ts": 1,
                "source_ip": 1, "user": 1, "hostname": 1, "rule_description": 1,
            },
        ).sort("event_ts", 1)

        async for doc in cursor:
            classes = set(doc.get("event_classes", []))
            if _AUTH_FAILURE in classes:
                failed += 1
            if _AUTH_SUCCESS in classes:
                success += 1
            ts = doc.get("event_ts")
            if ts is not None:
                first_seen = ts if first_seen is None else min(first_seen, ts)
                last_seen = ts if last_seen is None else max(last_seen, ts)
            events.append({
                "event_ts": ts.isoformat() if isinstance(ts, datetime) else str(ts),
                "classes": sorted(classes),
                "rule": doc.get("rule_description", ""),
                "source_ip": doc.get("source_ip", ""),
                "user": doc.get("user", ""),
            })
    except Exception as exc:  # noqa: BLE001 - never break the pipeline on a tool error
        logger.warning("get_login_history failed: %s", exc)

    return {
        "failed_logins": failed,
        "successful_logins": success,
        "total_events": len(events),
        "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else None,
        "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None,
        "window_minutes": window,
        "events": events[:25],  # cap payload handed to the LLM
    }


async def check_user_baseline(user: str, exclude_case_id: str | None = None) -> dict[str, Any]:
    """
    Compare a user against their history: how many prior cases involve them, and
    whether they've been seen before at all.

    Baseline here = "has this identity triggered cases before, and with what
    verdicts." A user with no prior benign history whose alerts spike reads as
    anomalous; a known user with routine history reads as within-baseline.
    """
    if not user:
        return {"prior_case_count": 0, "known_user": False, "deviation": "no user on alert"}

    query: dict[str, Any] = {"alert.user": user}
    if exclude_case_id:
        query["case_id"] = {"$ne": exclude_case_id}

    prior_count = 0
    verdicts: dict[str, int] = {}
    try:
        db = get_mongo_db()
        prior_count = await db.cases.count_documents(query)
        cursor = db.cases.find(query, {"_id": 0, "investigation.verdict": 1}).limit(50)
        async for doc in cursor:
            v = (doc.get("investigation") or {}).get("verdict")
            if v:
                verdicts[v] = verdicts.get(v, 0) + 1
    except Exception as exc:  # noqa: BLE001
        logger.warning("check_user_baseline failed: %s", exc)

    known = prior_count > 0
    if not known:
        deviation = "first time this user has appeared — no established baseline"
    elif verdicts.get("true_positive", 0) > 0:
        deviation = "user has prior true-positive cases — elevated risk"
    else:
        deviation = "user seen before, only benign/false-positive history"

    return {
        "prior_case_count": prior_count,
        "known_user": known,
        "prior_verdicts": verdicts,
        "deviation": deviation,
    }


def get_correlation_context(correlation: CorrelationContext | None) -> dict[str, Any]:
    """Read the correlation context already attached upstream (no DB call)."""
    if correlation is None:
        return {"pattern_matched": "", "related_alert_count": 0, "details": "no correlation context"}
    return {
        "pattern_matched": correlation.pattern_matched or "none",
        "related_alert_count": correlation.related_alert_count,
        "time_window_minutes": correlation.time_window_minutes,
        "related_alert_ids": correlation.related_alert_ids,
        "details": correlation.details,
    }


# ---------------------------------------------------------------------------
# RAG stubs — hardcoded now, ChromaDB-backed later (signatures are the contract)
# ---------------------------------------------------------------------------

# 8 techniques relevant to insider-threat / common attack patterns.
_MITRE_TECHNIQUES: list[dict[str, Any]] = [
    {"technique_id": "T1078", "name": "Valid Accounts",
     "description": "Adversaries obtain and abuse credentials of existing accounts to gain access and blend in.",
     "detection": "Successful logins after failures, logins from new IPs/geos, or off-baseline account use.",
     "keywords": ["valid account", "accepted password", "successful login", "authentication success", "login"]},
    {"technique_id": "T1110", "name": "Brute Force",
     "description": "Adversaries guess passwords via repeated authentication attempts.",
     "detection": "Many failed authentications from one source in a short window; failures then a success.",
     "keywords": ["brute force", "failed password", "authentication failed", "many failed", "repeated login"]},
    {"technique_id": "T1548", "name": "Abuse Elevation Control Mechanism",
     "description": "Adversaries circumvent controls to elevate privileges (e.g. sudo).",
     "detection": "Unexpected sudo/su usage, first-time sudo by a user, privilege changes after login.",
     "keywords": ["sudo", "privilege escalation", "elevation", "root", "su ", "first time user executed sudo"]},
    {"technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol",
     "description": "Adversaries steal data over a protocol different from the main C2 channel.",
     "detection": "Large or unusual outbound transfers to unfamiliar destinations.",
     "keywords": ["exfiltration", "data transfer", "outbound", "upload", "data leak"]},
    {"technique_id": "T1105", "name": "Ingress Tool Transfer",
     "description": "Adversaries transfer tools or files from an external system into the environment.",
     "detection": "Unexpected downloads of executables/scripts onto a host.",
     "keywords": ["download", "ingress", "tool transfer", "wget", "curl", "file transfer"]},
    {"technique_id": "T1531", "name": "Account Access Removal",
     "description": "Adversaries disrupt availability by removing or locking accounts.",
     "detection": "Unexpected account lockouts, password resets, or deletions.",
     "keywords": ["account removal", "account locked", "password reset", "account deleted", "lockout"]},
    {"technique_id": "T1485", "name": "Data Destruction",
     "description": "Adversaries destroy data and files to disrupt availability.",
     "detection": "Mass file deletion/overwrite, integrity changes on critical files.",
     "keywords": ["data destruction", "file deleted", "overwrite", "wiped", "integrity checksum changed"]},
    {"technique_id": "T1083", "name": "File and Directory Discovery",
     "description": "Adversaries enumerate files and directories to inform further actions.",
     "detection": "Enumeration commands, unusual access to many files/paths.",
     "keywords": ["file discovery", "directory discovery", "enumerate", "recon", "ls ", "find "]},
]

# Runbooks keyed by AlertType value.
_RUNBOOKS: dict[str, dict[str, Any]] = {
    "auth_failure": {
        "runbook_id": "RB-AUTH-BRUTEFORCE",
        "title": "SSH brute force / credential attack response",
        "steps": ["Block the source IP at the firewall", "Lock the targeted account",
                  "Force password reset", "Review auth logs for a successful login from the same IP"],
        "recommended_actions": [
            {"action": "block_ip", "is_destructive": True},
            {"action": "disable_account", "is_destructive": True},
        ],
    },
    "priv_escalation": {
        "runbook_id": "RB-PRIVESC",
        "title": "Privilege escalation response",
        "steps": ["Isolate the affected host", "Revoke the user's elevated sessions",
                  "Audit sudoers and recent privileged commands", "Reset the compromised account"],
        "recommended_actions": [
            {"action": "isolate_host", "is_destructive": True},
            {"action": "disable_account", "is_destructive": True},
        ],
    },
    "file_integrity": {
        "runbook_id": "RB-FIM",
        "title": "File integrity violation response",
        "steps": ["Snapshot the affected files", "Compare against known-good baseline",
                  "Restore from backup if tampered", "Investigate the process that made the change"],
        "recommended_actions": [
            {"action": "snapshot_host", "is_destructive": False},
            {"action": "raise_severity", "is_destructive": False},
        ],
    },
    "network_anomaly": {
        "runbook_id": "RB-NET-RECON",
        "title": "Network anomaly / reconnaissance response",
        "steps": ["Identify scanned assets", "Block the scanning source",
                  "Increase monitoring on targeted hosts"],
        "recommended_actions": [
            {"action": "block_ip", "is_destructive": True},
            {"action": "raise_severity", "is_destructive": False},
        ],
    },
    "data_access": {
        "runbook_id": "RB-DATA-EXFIL",
        "title": "Data access / exfiltration response",
        "steps": ["Identify accessed data", "Block outbound to the destination",
                  "Revoke the user's data access", "Engage data-owner and legal if confirmed"],
        "recommended_actions": [
            {"action": "block_ip", "is_destructive": True},
            {"action": "disable_account", "is_destructive": True},
        ],
    },
}


def query_mitre_attack(evidence_summary: str, n_results: int = 3) -> list[dict[str, Any]]:
    """
    Return MITRE ATT&CK techniques matching an evidence summary.

    STUB: keyword-scores the hardcoded corpus. Signature matches the future
    RAGStore-backed retrieval (text in, ranked technique docs out).
    """
    text = (evidence_summary or "").lower()
    scored: list[tuple[int, dict[str, Any]]] = []
    for tech in _MITRE_TECHNIQUES:
        score = sum(1 for kw in tech["keywords"] if kw in text)
        if score:
            scored.append((score, tech))

    scored.sort(key=lambda pair: pair[0], reverse=True)
    results = [
        {k: t[k] for k in ("technique_id", "name", "description", "detection")}
        for _, t in scored[:n_results]
    ]
    logger.debug("query_mitre_attack matched %d technique(s)", len(results))
    return results


def query_runbooks(alert_type: str, n_results: int = 1) -> dict[str, Any]:
    """
    Return the response runbook for an alert type.

    STUB: direct map over the hardcoded runbook library. Signature matches the
    future RAGStore-backed retrieval.
    """
    runbook = _RUNBOOKS.get((alert_type or "").lower())
    if runbook is None:
        return {
            "runbook_id": "RB-GENERIC",
            "title": "Generic triage — no specific runbook matched",
            "steps": ["Escalate to a human analyst for manual review"],
            "recommended_actions": [{"action": "raise_severity", "is_destructive": False}],
        }
    return runbook
