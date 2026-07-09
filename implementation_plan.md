# Agentic AI SOC Platform — Implementation Plan

## Assessment

Your plan is **solid and well-sequenced**. The bottom-up approach (infra skeleton → real ingestion → correlation → enrichment → agents → observability → mTLS) is exactly right. I have a few refinements:

> [!TIP]
> **What I'd change from your tentative plan:**
> 1. **Define Pydantic models in Phase 0**, not later — every layer needs to agree on the alert/case schema from the start
> 2. **Build the worker loop in Phase 0** as a proper service (not a throwaway script) — it becomes the correlation/enrichment/agent pipeline runner
> 3. **Defer Wazuh Docker install to Phase 1** — don't let Wazuh finickiness block your skeleton validation. Use `curl` with a realistic Wazuh JSON payload for Phase 0
> 4. **Fold Decision Agent into Investigation Agent's output** — your plan already suggests this as an option, and it saves a full LLM round-trip without losing any capability
> 5. **Build RAG ingestion as a standalone script** before wiring it into agents — easier to debug

> [!IMPORTANT]
> **Key dependencies to have ready before starting:**
> - Groq API key (for Llama 3.3 70B)
> - AlienVault OTX API key (free tier)
> - Slack webhook URL (for notifications)
> - Docker & Docker Compose installed

---

## Phase 0 — Infrastructure Skeleton (Day 1, morning)

**Goal:** Docker Compose with FastAPI + Redis + MongoDB talking to each other. A `curl` POST → lands in Redis → lands in MongoDB.

### Data Models (shared foundation)

#### [NEW] [models.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/models.py)
Define all Pydantic models upfront — every downstream layer imports from here:
- `WazuhAlert` — raw incoming Wazuh JSON shape
- `NormalizedAlert` — internal schema (alert_id, timestamp, source_ip, dest_ip, user, rule_id, rule_level, rule_description, hostname, alert_type, raw_payload)
- `CorrelationContext` — attached by correlation engine (related_alerts count, pattern_matched, time_window_minutes, related_alert_ids)
- `EnrichmentContext` — attached by enrichment engine (otx_reputation, asset_criticality, historical_case_count, historical_cases)
- `EnrichedAlert` — NormalizedAlert + CorrelationContext + EnrichmentContext
- `CaseDocument` — full MongoDB case (case_id, alert, triage, investigation, decision, verification, remediation, report, status, timestamps, analyst_feedback)
- `AgentOutput` — base model for each agent's structured output

#### [NEW] [config.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/config.py)
Centralized settings via `pydantic-settings`:
- Redis URL, MongoDB URL, Groq API key, OTX API key, Slack webhook URL
- All from environment variables with sensible defaults for local Docker

#### [NEW] [database.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/database.py)
- `get_mongo_client()` / `get_mongo_db()` — Motor async MongoDB client
- `get_redis_client()` — aioredis client
- Connection pooling and health check helpers

---

### Ingestion Service

#### [NEW] [main.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/ingestion/main.py)
FastAPI app with:
- `POST /api/v1/alerts/wazuh` — receives Wazuh webhook, validates auth token (simple Bearer token from header), parses JSON into `NormalizedAlert`, pushes to Redis `alerts:incoming` list. On parse failure → pushes raw payload to Redis `alerts:dlq` list
- `GET /api/v1/health` — health check (Redis + MongoDB ping)
- `GET /metrics` — Prometheus metrics endpoint (using `prometheus-fastapi-instrumentator`)
- Startup/shutdown lifespan managing Redis and MongoDB connections

#### [NEW] [Dockerfile](file:///home/kernelops/Projects/agentic-ai-soc-platform/ingestion/Dockerfile)
Python 3.11-slim, install requirements, run uvicorn

#### [NEW] [requirements.txt](file:///home/kernelops/Projects/agentic-ai-soc-platform/ingestion/requirements.txt)
fastapi, uvicorn, redis, motor, pydantic, pydantic-settings, prometheus-fastapi-instrumentator

---

### Pipeline Worker

#### [NEW] [worker.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/worker.py)
The main pipeline runner — an async loop that:
1. `BRPOP` from Redis `alerts:incoming`
2. Deserializes to `NormalizedAlert`
3. (Phase 0: just writes directly to MongoDB `alerts` collection)
4. (Later phases: correlation → enrichment → agent pipeline → MongoDB)

This is **not** a throwaway script — it becomes the actual pipeline orchestrator.

#### [NEW] [Dockerfile](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/Dockerfile)
Same Python base, runs `worker.py`

---

### Infrastructure

#### [NEW] [docker-compose.yml](file:///home/kernelops/Projects/agentic-ai-soc-platform/docker-compose.yml)
Services:
- `ingestion` — FastAPI on port 8000
- `worker` — pipeline worker
- `redis` — Redis 7 on port 6379
- `mongodb` — MongoDB 7 on port 27017
- Shared network `soc-network`
- Volume mounts for MongoDB data persistence

#### [NEW] [.env.example](file:///home/kernelops/Projects/agentic-ai-soc-platform/.env.example)
Template for all required environment variables

### Phase 0 Verification
```bash
# Start everything
docker compose up --build -d

# Send a fake alert
curl -X POST http://localhost:8000/api/v1/alerts/wazuh \
  -H "Authorization: Bearer test-token" \
  -H "Content-Type: application/json" \
  -d '{"id": "1234", "rule": {"level": 10, "description": "SSH brute force"}, ...}'

# Confirm it landed in MongoDB
docker exec -it mongodb mongosh --eval "db.alerts.find().pretty()"
```

---

## Phase 1 — Real Wazuh Ingestion (Day 1, afternoon)

**Goal:** Wazuh running in Docker, firing real alerts that land in Redis → MongoDB.

### Wazuh Setup

#### [NEW] [docker-compose.wazuh.yml](file:///home/kernelops/Projects/agentic-ai-soc-platform/docker-compose.wazuh.yml)
Separate compose file for Wazuh stack (manager + indexer + dashboard). Kept separate because Wazuh is heavy and you may want to start/stop it independently.

#### [NEW] [wazuh-integration.sh](file:///home/kernelops/Projects/agentic-ai-soc-platform/infrastructure/wazuh/wazuh-integration.sh)
Custom integration script that POSTs alerts to the FastAPI ingestion endpoint. Placed in Wazuh's `integrations/` directory.

#### [MODIFY] [main.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/ingestion/main.py)
- Refine the Wazuh JSON parser to handle real Wazuh alert format (nested `rule`, `agent`, `data` fields)
- Robust error handling — any parse failure → DLQ with the raw payload + error message
- Add Prometheus counters: `alerts_received_total`, `alerts_parsed_total`, `alerts_dlq_total`

### Phase 1 Verification
```bash
# Trigger a real failed SSH login on the monitored host
ssh baduser@monitored-host  # intentionally fail

# Check Redis queue, then MongoDB
```

---

## Phase 2 — Correlation Engine (Day 2, first half)

**Goal:** Alerts get a `correlation_context` attached before moving forward.

#### [NEW] [engine.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/correlation/engine.py)
- `CorrelationEngine` class with async `correlate(alert: NormalizedAlert) -> CorrelationContext`
- Queries MongoDB `recent_alerts` collection (TTL index, 30-min window) for matching IP/user/host
- **Rule 1:** Brute force — 3+ failed logins from same IP in 5-min window
- **Rule 2:** Brute force then login — failed logins followed by successful login from same IP in 10-min window
- **Rule 3:** Privilege escalation after login — successful login followed by priv-esc event from same user in 10-min window
- Stores each incoming alert in `recent_alerts` for future correlation lookups

#### [NEW] [rules.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/correlation/rules.py)
Each rule as a separate function: `check_brute_force()`, `check_brute_force_then_login()`, `check_priv_esc_after_login()`. Returns `(pattern_name, matched_alert_ids, time_window)` or `None`.

#### [MODIFY] [worker.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/worker.py)
Wire correlation into the pipeline: after deserializing alert, call `correlation_engine.correlate(alert)` and attach the result.

---

## Phase 3 — Enrichment Engine (Day 2, second half)

**Goal:** Alerts carry OTX reputation, asset criticality, and historical context.

#### [NEW] [otx.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/enrichment/otx.py)
- `OTXEnricher` — async `httpx` call to AlienVault OTX API (`/api/v1/indicators/IPv4/{ip}/general`)
- Returns reputation score, pulse count, known malicious flag
- Caches results in Redis (1-hour TTL) to avoid hammering the API

#### [NEW] [asset_context.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/enrichment/asset_context.py)
- Hardcoded dict for demo: `{"prod-db-01": "critical", "prod-web-01": "high", "staging-01": "medium", "dev-vm-03": "low"}`
- `get_asset_criticality(hostname: str) -> str`

#### [NEW] [historical.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/enrichment/historical.py)
- `HistoricalEnricher` — queries MongoDB `cases` collection for past cases matching IP or user
- Returns count + summaries of prior incidents

#### [NEW] [engine.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/enrichment/engine.py)
- `EnrichmentEngine` — orchestrates all three enrichers in parallel (`asyncio.gather`)
- Returns `EnrichmentContext`

#### [MODIFY] [worker.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/worker.py)
Wire enrichment after correlation: `enrichment_engine.enrich(alert, correlation_context)`.

**Checkpoint:** An alert now arrives at the agent layer carrying: normalized data + correlation context + enrichment context.

---

## Phase 4 — RAG Knowledge Layer (Day 3, first task)

**Goal:** ChromaDB populated with MITRE ATT&CK techniques, runbooks, and ready for past-case ingestion.

#### [NEW] [store.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/rag/store.py)
- `RAGStore` class wrapping ChromaDB client
- Three collections: `mitre_attack`, `runbooks`, `past_cases`
- `query(collection, text, n_results)` → returns relevant documents with metadata
- `add_document(collection, text, metadata)` → for feedback loop

#### [NEW] [ingest.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/rag/ingest.py)
Standalone script to populate ChromaDB:
- **MITRE ATT&CK corpus** (8 techniques): T1078, T1110, T1548, T1048, T1105, T1531, T1485, T1083 — each as a structured document with technique ID, name, description, detection guidance, and typical indicators
- **Runbooks** (5-6): SSH brute force response, privilege escalation response, file integrity violation response, data exfiltration response, account compromise response — each with step-by-step actions

#### [NEW] [data/mitre_techniques.json](file:///home/kernelops/Projects/agentic-ai-soc-platform/rag/data/mitre_techniques.json)
Structured MITRE ATT&CK data for the 8 selected techniques.

#### [NEW] [data/runbooks.json](file:///home/kernelops/Projects/agentic-ai-soc-platform/rag/data/runbooks.json)
Structured runbook data.

---

## Phase 5 — Agentic Layer (Days 3-4, main block)

**Goal:** Full LangGraph sequential pipeline — Dispatcher → Triage → Investigation → Decision → Verification → Remediation → Reporting.

> [!IMPORTANT]
> **Build order matters.** Build and test each agent in isolation before wiring into the graph. Don't try to debug all 6 agents at once.

### LangGraph Pipeline

#### [NEW] [pipeline.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/pipeline.py)
- LangGraph `StateGraph` definition
- State schema: `PipelineState` (enriched_alert, case_id, triage_output, investigation_output, decision, verification_output, remediation_output, report, current_stage)
- Node wiring: dispatcher → triage → investigation → decision_router → [verification | reporting] → [remediation | reporting] → reporting
- Conditional edges: decision_router branches on true_positive/false_positive; verification branches on verified/rejected

#### [NEW] [state.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/state.py)
- `PipelineState` TypedDict for LangGraph state

---

### Individual Agents (build in this order)

#### [NEW] [dispatcher.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/dispatcher.py)
**No LLM call.** Creates case document in MongoDB, generates case_id, initializes pipeline state. Pure logic.

#### [NEW] [triage.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/triage.py)
**First LLM call.** Prompt receives: alert data + enrichment context. Outputs: `alert_type` (enum: auth_failure, priv_escalation, file_integrity, network_anomaly, data_access), `initial_severity` (1-10), `reasoning`.

#### [NEW] [investigation.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/investigation.py)
**Core reasoning agent with tool calling.** Tools:
- `get_login_history(user_or_ip)` — queries MongoDB
- `check_user_baseline(user)` — compares against typical patterns
- `get_correlation_context()` — reads the already-attached correlation data
- `query_mitre_attack(evidence_summary)` — RAG retrieval from ChromaDB

Outputs structured evidence report with: timeline, baseline comparison, matched MITRE techniques, and a **verdict** (true_positive / false_positive) with confidence score + final severity.

> [!NOTE]
> Decision Agent is folded into Investigation's final output — the investigation naturally concludes with a verdict. This saves a full LLM round-trip.

#### [NEW] [verification.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/verification.py)
**Hallucination guard.** Only runs on true positives. Independent LLM call that receives the investigation output and checks:
- Does the evidence actually support the verdict?
- Is the MITRE technique citation a genuine match?
- Any policy violations? (e.g., never auto-remediate admin accounts)

Outputs: `verified` (bool), `rejection_reason` (if rejected), `confidence_score`.

#### [NEW] [remediation.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/remediation.py)
**Only on verified true positives.** Queries RAG runbook collection, drafts specific actions (block IP, disable account, etc.). Outputs: `proposed_actions[]`, `is_destructive` (bool), `runbook_reference`.

#### [NEW] [approval.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/approval.py)
**Not an LLM call.** Pipeline pause. For destructive actions: sets case status to `pending_approval` in MongoDB, sends Slack notification. Polls MongoDB for approval flag (or receives webhook callback). Non-destructive actions skip this.

#### [NEW] [reporting.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/reporting.py)
**Always runs.** LLM call to generate structured incident report. Writes final report to case document. Triggers Slack notification for high-severity cases.

---

### Agent Utilities

#### [NEW] [llm.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/llm.py)
- `get_llm()` — returns configured ChatGroq (Llama 3.3 70B) instance
- Shared across all LLM-calling agents
- Retry logic for API rate limits

#### [NEW] [tools.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/agents/tools.py)
- All tool definitions as LangChain `@tool` decorated functions
- `get_login_history`, `check_user_baseline`, `get_correlation_context`, `query_mitre_attack`, `query_runbooks`

#### [MODIFY] [worker.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/worker.py)
Wire the full pipeline: after enrichment, invoke the LangGraph pipeline with the enriched alert.

---

## Phase 6 — Observability (Day 5, first half)

**Goal:** Prometheus + Grafana + Slack notifications operational.

#### [NEW] [prometheus.yml](file:///home/kernelops/Projects/agentic-ai-soc-platform/infrastructure/prometheus/prometheus.yml)
Scrape config targeting: ingestion FastAPI `/metrics`, worker metrics endpoint.

#### [NEW] [dashboards/soc_dashboard.json](file:///home/kernelops/Projects/agentic-ai-soc-platform/infrastructure/grafana/dashboards/soc_dashboard.json)
Grafana dashboard (provisioned via JSON):
- Panel 1: Alert volume over time
- Panel 2: Severity breakdown (pie chart)
- Panel 3: Case status distribution (open/investigating/resolved)
- Panel 4: Agent verdict distribution (true_positive/false_positive/rejected)

#### [NEW] [datasources.yml](file:///home/kernelops/Projects/agentic-ai-soc-platform/infrastructure/grafana/provisioning/datasources.yml)
Prometheus datasource auto-provisioning.

#### [NEW] [notifications.py](file:///home/kernelops/Projects/agentic-ai-soc-platform/common/notifications.py)
Slack webhook integration — `send_slack_alert(case)` for high-severity cases and approval requests.

#### [MODIFY] [docker-compose.yml](file:///home/kernelops/Projects/agentic-ai-soc-platform/docker-compose.yml)
Add `prometheus` and `grafana` services.

---

## Phase 7 — mTLS & Demo Polish (Day 5, second half)

**Goal:** TLS client cert auth on admin routes, polished demo script.

#### [NEW] [generate_certs.sh](file:///home/kernelops/Projects/agentic-ai-soc-platform/infrastructure/pki/generate_certs.sh)
OpenSSL script:
1. Generate self-signed root CA
2. Issue server cert for NGINX
3. Issue client cert for admin/analyst access

#### [NEW] [nginx.conf](file:///home/kernelops/Projects/agentic-ai-soc-platform/infrastructure/nginx/nginx.conf)
- Proxy pass to FastAPI ingestion service
- Proxy pass to Grafana dashboard
- `ssl_client_certificate` on `/admin/` routes — reject without valid client cert
- Standard TLS on all other routes

#### [NEW] [demo_attack.sh](file:///home/kernelops/Projects/agentic-ai-soc-platform/tests/demo_attack.sh)
Automated demo script:
1. "Alice" normal login (single fail then success) → expect false positive
2. "Bob" brute force attack (5 rapid fails → success → priv-esc) → expect true positive → full pipeline
3. mTLS demo: curl without cert → rejected; curl with cert → accepted

#### [MODIFY] [docker-compose.yml](file:///home/kernelops/Projects/agentic-ai-soc-platform/docker-compose.yml)
Add `nginx` service with cert volume mounts.

---

## Open Questions

> [!IMPORTANT]
> 1. **Groq API key** — do you have one ready, or should I stub the LLM calls for initial development?
> 2. **Wazuh deployment** — do you want Wazuh in the same Docker Compose, or a separate compose file? (I'm suggesting separate for isolation given how heavy it is)
> 3. **Monitored host** — will you use a separate VM, or should we add a lightweight container to the compose that acts as the "monitored host"?
> 4. **Slack workspace** — do you have a webhook URL, or should we use a simple HTTP callback + MongoDB flag for the approval gate instead?

---

## Verification Plan

### Automated Tests
- **Phase 0:** `curl` POST → check Redis → check MongoDB (integration test)
- **Phase 1:** Trigger real Wazuh alert → verify it lands in Redis and MongoDB
- **Phase 2:** Send 5 rapid failed-login alerts → verify correlation_context shows brute_force pattern
- **Phase 3:** Send alert with known-malicious IP → verify OTX enrichment attached
- **Phase 4:** Query ChromaDB for "brute force" → verify T1110 returned
- **Phase 5:** Send enriched alert through pipeline → verify case document in MongoDB has all agent outputs
- **Phase 6:** Check Grafana dashboard shows live data
- **Phase 7:** `curl` without cert → 403; with cert → 200

### Manual Verification
- Full demo script run-through (3-4 times)
- Grafana dashboard visual check
- Slack notification delivery check

### End-to-End Test
```bash
# The final validation: run demo_attack.sh and trace a single alert
# from Wazuh → Redis → Correlation → Enrichment → All Agents → MongoDB → Grafana
```
