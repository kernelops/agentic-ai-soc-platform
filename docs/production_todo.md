# Production Hardening TODO

Running list of non-blocking items to address before/for live operation (real
Wazuh alerts, sustained load). These are deferred by choice, not bugs — the
current behavior is correct, these make it production-grade. Grouped by phase.

## Phase 3 — Enrichment

### 1. Populate the asset criticality map with real hosts
- **Where:** `common/config.py` → `asset_criticality_map`
- **What:** It currently holds demo hostnames (`prod-db-01`, `prod-web-01`,
  `victim-kali`, etc.). Real Wazuh agents will report different names, so those
  hosts resolve to `unknown`.
- **Action:** Replace with the actual monitored host names (or load from a
  mounted JSON / CMDB). Overridable today via `SOC_ASSET_CRITICALITY_MAP` as a
  JSON env var.

### 2. Decouple enrichment from the single worker loop (throughput)
- **Where:** `common/worker.py` (sequential `BRPOP` loop) + `enrichment/otx.py`
- **What:** The worker processes alerts one at a time and each *new* public IP
  blocks on the OTX call (read timeout up to 15s — OTX `/general` can genuinely
  take ~13s for heavily-referenced IPs). Caching bounds this to once per IP
  (1h success cache / 120s negative cache), so a single-source attack only
  stalls on the first alert. But a burst from many distinct IPs would serialize
  and back the queue up.
- **Action (when hardening scale):** concurrent alert processing (worker pool),
  or a short OTX time budget with async backfill of reputation after the case
  is written.

### 3. Historical lookup: distinguish prior incidents from same-burst alerts
- **Where:** `enrichment/historical.py`
- **What:** `historical_case_count` counts *all* prior cases matching IP/user,
  including other alerts from the same in-flight burst (seconds apart). Useful
  as raw signal, but inflates "have we seen this before" for an ongoing attack.
- **Action:** Optionally exclude alerts within the current correlation window
  (the correlation context already identifies which alerts belong to this
  burst), so historical means "seen before this incident."

### 4. (Optional) Derive a meaningful OTX reputation_score
- **Where:** `enrichment/otx.py` → `_parse`
- **What:** OTX `/general` returns `reputation` as `0`/null almost always
  (deprecated scoring), so `reputation_score` is uninformative. The real signal
  is `pulse_count` + `is_known_malicious`.
- **Action:** Optionally bucket `pulse_count` into a 0-100 severity score if a
  numeric score is wanted downstream.

## Tooling / minor

### 5. send_alerts.py CLI flag ordering is inconsistent
- **Where:** `tests/send_alerts.py`
- **What:** `--url` / `--token` / `--delay` are top-level (must come *before*
  the subcommand); `--srcip` / `--count` are on the subparser (must come
  *after*). Functional but easy to trip over.
- **Action:** Optionally move all shared flags onto a common parent parser so
  they work in one consistent position.

## Environment notes (not code)

- **Container egress to OTX:** occasional transient DNS/read flakiness observed
  from the Docker bridge on this host; resolved on retry. If it recurs
  persistently, revisit container DNS (`dns:` on services) or MTU
  (`com.docker.network.driver.mtu` on `soc-network`).
