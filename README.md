# Agentic AI SOC Platform

An Agentic AI–powered Security Operations Center (SOC) platform integrating Wazuh SIEM, rule-based correlation, threat-intelligence enrichment, a LangGraph multi-agent pipeline, RAG-based security knowledge, human approval gates, a read API, and a dashboard UI for automated incident investigation and response.

## What works today (Phases 0–5 + API + UI)

An ingested alert flows end to end:

```
alert (curl) → ingestion (FastAPI) → Redis → worker
     → correlation (rules) → enrichment (OTX + asset + history)
     → agentic pipeline (triage → investigation → verification → remediation → approval → reporting)
     → MongoDB case  →  API  →  Dashboard UI
```

- **Ingestion** — normalizes Wazuh JSON, queues to Redis.
- **Correlation** — rules-based patterns (brute force, brute-force-then-login, priv-esc-after-login).
- **Enrichment** — AlienVault OTX reputation, asset criticality, historical case lookup.
- **Agents** — LangGraph pipeline on Groq (Llama 3.3 70B) with a human approval gate for destructive actions.
- **RAG** — Qdrant + FastEmbed knowledge base (MITRE ATT&CK techniques + response runbooks) grounding the agents.
- **API** — FastAPI read/query service powering the UI (`:8080`).
- **UI** — React dashboard with 7 tabs (`:3000` in Docker, `:5173` in dev).

Observability (Prometheus/Grafana) and mTLS are not yet wired in.

## Directory structure

- `ingestion/` — FastAPI service parsing/normalizing Wazuh alerts.
- `correlation/` — rules-based correlation engine + classifier.
- `enrichment/` — OTX threat intel, asset context, historical lookup.
- `agents/` — LangGraph agent pipeline (dispatcher, triage, investigation, verification, remediation, approval, reporting).
- `rag/` — Qdrant-backed knowledge store + ingest script + MITRE/runbook data.
- `api/` — read/query API + case actions powering the UI.
- `ui/` — React + Vite + TypeScript + Tailwind dashboard.
- `common/` — shared config, database clients, Pydantic models, pipeline worker.
- `infrastructure/` — Wazuh stack, and (later) NGINX/PKI/Prometheus/Grafana.
- `tests/` — the curl-based alert sender and fixtures.
- `docs/` — design notes and the production-hardening TODO.

---

## Prerequisites

- Docker + Docker Compose
- Node.js 18+ and npm (only if you want to run the UI in dev mode)
- A **Groq API key** (required for the agent pipeline) — the agents need this
- An **AlienVault OTX API key** (optional — enables live IP threat intel)

Copy the env template and fill in your keys:

```bash
cp .env.example .env
# set at minimum:
#   SOC_GROQ_API_KEY=<your groq key>
#   SOC_OTX_API_KEY=<your otx key>   # optional
```

---

## End-to-end test

### 1. Start the backend stack

The main stack owns the shared `soc-network`, so no manual network setup is needed.

```bash
docker compose up -d --build redis mongodb qdrant ingestion api worker
docker compose ps
```

Expect `soc-redis`, `soc-mongodb`, `soc-qdrant`, `soc-ingestion`, `soc-api`, and `soc-worker` all running (redis/mongo report healthy).

### 2. Confirm the Groq key reached the worker

```bash
docker exec soc-worker python -c "from common.config import settings; print('groq key length:', len(settings.groq_api_key), '| model:', settings.groq_model)"
```

A non-zero length means the agents can run. If it prints `0`, set `SOC_GROQ_API_KEY` in `.env` and rerun step 1.

### 3. Populate the RAG knowledge base (Qdrant)

```bash
docker compose run --rm worker python -m rag.ingest
```

Expect `Ingestion complete: 8 MITRE techniques, 7 runbooks`. Verify:

```bash
curl -s http://localhost:6333/collections | python3 -m json.tool
```

### 4. Sanity-check the API

```bash
curl -s http://localhost:8080/api/v1/health
curl -s "http://localhost:8080/api/v1/system/health" | python3 -m json.tool | head -30
```

Interactive API docs: **http://localhost:8080/docs**

### 5. Start the UI

**Option A — dev mode (fast, shows build errors):**

```bash
cd ui
npm install
npm run dev
```

Open **http://localhost:5173** (Vite proxies `/api` and the WebSocket to the API on `:8080`).

**Option B — containerized (nginx):**

```bash
docker compose up -d --build ui
```

Open **http://localhost:3000**.

### 6. Drive the pipeline with realistic Wazuh alerts

Until the live Wazuh + Kali-agent setup is wired (see `infrastructure/wazuh/README.md`), the pipeline is exercised with genuine Wazuh alert JSON sent over HTTP:

```bash
# Benign case (single failed login then success) — expect false_positive, auto-closed
python tests/send_alerts.py alice

# Attack case (brute-force burst -> login -> sudo priv-esc, same IP/user)
python tests/send_alerts.py bob --count 5

# Attack from a real public IP — exercises live OTX threat intel
python tests/send_alerts.py bob --srcip 185.220.101.1

# Send a single canonical fixture
python tests/send_alerts.py fixture sudo_privesc
```

Give the agent pipeline a minute per burst — it makes several sequential Groq calls per alert and backs off on free-tier rate limits (this is expected and handled).

### 7. What to check in the UI

- **Footer** — "WS Connected", live queue depth, alerts/hr, worker dot, model `llama-3.3-70b-versatile`.
- **Dashboard** — counters, alert-volume chart, top attacked assets.
- **Alerts** — filterable/searchable table; Export JSON; row → detail drawer.
- **Correlation** — pattern chips; select a case → its linked alert cluster.
- **Enrichment** — the `185.220.101.1` case shows a malicious OTX badge; asset criticality mix.
- **Agent Ops** — open a bob case → Triage → Investigation (verdict `true_positive`, MITRE **T1110/T1548**) → Verification → Remediation → **Approve / Reject** on `pending_approval` cases.
- **System Health** — a card per service with up/down status and latency.
- **Analytics** — alert volume by severity, verdict distribution, resolution stats.

### 8. Verify from the database (optional)

```bash
# Alice -> benign
docker exec soc-mongodb mongosh --quiet --eval "db=db.getSiblingDB('soc_platform'); db.cases.find({'alert.user':'alice'},{status:1,'investigation.verdict':1}).sort({created_at:-1}).limit(1).pretty()"

# Bob -> true positive, pending approval, MITRE + runbook remediation
docker exec soc-mongodb mongosh --quiet --eval "db=db.getSiblingDB('soc_platform'); db.cases.find({'alert.user':'baduser'},{status:1,'investigation.verdict':1,'investigation.matched_mitre_techniques':1,'verification.verified':1,'remediation.runbook_reference':1}).sort({created_at:-1}).limit(2).pretty()"
```

---

## Ports

| Service | Port | Notes |
|---|---|---|
| UI (nginx) | 3000 | Docker build of the dashboard |
| UI (Vite dev) | 5173 | `npm run dev`, proxies to API |
| Ingestion API | 8000 | Wazuh webhook + health |
| Read API | 8080 | Powers the UI; docs at `/docs` |
| Qdrant | 6333 / 6334 | Vector store REST / gRPC |
| Redis | 6380 | Host port (container 6379) |
| MongoDB | 27018 | Host port (container 27017) |

## Reset to a clean slate

```bash
docker exec soc-mongodb mongosh --quiet --eval "db=db.getSiblingDB('soc_platform'); db.cases.deleteMany({}); db.recent_alerts.deleteMany({}); print('cleared')"
```

## Troubleshooting

- **Cases stuck before `reporting`, or verdict `unverified`** — the agent hit Groq rate limits and exhausted retries. Re-run with fewer alerts, or use a higher Groq tier.
- **`otx_reputation: null` for a public IP** — OTX can be slow for heavily-referenced IPs; the first lookup per IP is cached. Internal `10.0.0.x` IPs are intentionally not looked up.
- **UI shows no data** — confirm the API is healthy (`curl :8080/api/v1/health`) and that you've sent alerts (step 6).
- **Worker shows "down" in System Health** — the worker refreshes a Redis heartbeat each loop; if it's down, check `docker logs soc-worker`.

## Notes for contributors

- Every ingested alert becomes one **case** document in MongoDB that accumulates data as it moves through the pipeline; the UI tabs are different lenses on that collection.
- Deferred production-hardening items are tracked in `docs/production_todo.md`.
