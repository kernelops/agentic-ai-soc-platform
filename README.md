# Agentic AI SOC Platform

An agentic, AI-powered Security Operations Center. Security alerts (from Wazuh, or replayed as realistic JSON) are ingested, correlated, enriched with threat intelligence, and then investigated end-to-end by a pipeline of LLM agents that triage, investigate, verify, and draft remediation — pausing for human approval before anything destructive. Everything is observable in a dashboard UI and behind a TLS/mTLS gateway.

## What it does

```
alert → ingestion (FastAPI) → Redis → worker
  → correlation (rules)      : brute force, brute-force-then-login, priv-esc-after-login
  → enrichment               : AlienVault OTX reputation + asset criticality + case history
  → agentic pipeline (Groq)  : triage → investigation → verification → remediation → approval → reporting
  → MongoDB case → read API → dashboard UI

served over an nginx TLS/mTLS gateway · metrics scraped by Prometheus/Grafana
```

- **Ingestion** — normalizes Wazuh JSON and queues it to Redis.
- **Correlation** — deterministic rules that link related alerts across IP / user / host.
- **Enrichment** — OTX IP reputation, asset criticality, and prior-case lookup.
- **Agents** — a LangGraph pipeline on Groq (Llama 3.3 70B), grounded in a **RAG** knowledge base (Qdrant + FastEmbed: MITRE ATT&CK techniques + response runbooks), with a **human approval gate** for destructive actions.
- **API + UI** — a FastAPI read/query service and a React dashboard (Dashboard, Alerts, Correlation, Enrichment, Agent Ops, System Health, Analytics).
- **Observability** — Prometheus + Grafana + cAdvisor.
- **Security** — an nginx edge gateway terminating TLS, enforcing **mutual TLS** on the approve/reject actions.

Every ingested alert becomes one **case** document in MongoDB that accumulates data as it moves through the pipeline; the UI tabs are different lenses on that collection.

## Architecture

- `ingestion/` — FastAPI webhook that parses/normalizes Wazuh alerts.
- `correlation/` — rules-based correlation engine + classifier.
- `enrichment/` — OTX threat intel, asset context, historical lookup.
- `agents/` — LangGraph agent pipeline (dispatcher → triage → investigation → verification → remediation → approval → reporting).
- `rag/` — Qdrant-backed knowledge store + ingest script + MITRE/runbook data.
- `api/` — read/query API + case actions powering the UI.
- `frontend/` — React + Vite + TypeScript + Tailwind dashboard.
- `common/` — shared config, database clients, Pydantic models, and the pipeline worker.
- `infrastructure/` — nginx gateway, PKI cert generation, Prometheus/Grafana, and the Wazuh stack.
- `tests/` — the curl-based alert sender, fixtures, and the mTLS demo script.
- `docs/` — design notes and the production-hardening TODO.

---

## Prerequisites

- **Docker + Docker Compose** (runs the entire stack; no local Python/Node needed).
- A **Groq API key** — required for the agent pipeline.
- An **AlienVault OTX API key** — optional; enables live IP threat intelligence.
- (Optional) **Node.js 18+** only if you want to run the UI in hot-reload dev mode.

---

## Set up & run the whole project

### 1. Configure environment

```bash
cp .env.example .env
# then edit .env and set at minimum:
#   SOC_GROQ_API_KEY=<your groq key>
#   SOC_OTX_API_KEY=<your otx key>    # optional
```

### 2. Generate the TLS/mTLS certificates

The gateway won't start without these. Run once (regenerate anytime with `--force`):

```bash
bash infrastructure/pki/generate_certs.sh
```

Creates a root CA, the gateway server cert, and an analyst client cert + `analyst.p12` (browser-import password: `analyst`) under `infrastructure/pki/`. All key/cert material is git-ignored.

### 3. Launch the full stack

```bash
docker compose up -d --build
```

This builds and starts everything: redis, mongodb, qdrant, ingestion, worker, api, ui, prometheus, grafana, cadvisor, and the gateway. **The first build takes several minutes** (frontend build + the embedding model is baked into the worker image). Check it came up:

```bash
docker compose ps
```

### 4. Load the RAG knowledge base

```bash
docker compose run --rm worker python -m rag.ingest
```

Expect `Ingestion complete: 8 MITRE techniques, 7 runbooks`.

### 5. Send some alerts through the pipeline

Until live Wazuh is wired in (see `infrastructure/wazuh/README.md`), drive it with realistic Wazuh alert JSON:

```bash
python3 tests/send_alerts.py alice                      # benign -> false positive, auto-closed
python3 tests/send_alerts.py bob --count 5              # attack -> true positive -> pending approval
python3 tests/send_alerts.py bob --srcip 185.220.101.1  # attack from a real public IP (live OTX hit)
```

Give the agents a minute per burst — they make several sequential Groq calls per alert and back off on free-tier rate limits (expected and handled).

> `send_alerts.py` uses only the Python standard library, so no `pip install` is needed.

### 6. Open the dashboard

| What | URL |
|---|---|
| **Dashboard (secure, via gateway)** | **https://localhost** — trust `infrastructure/pki/ca.crt` or accept the self-signed warning |
| Dashboard (direct, dev convenience) | http://localhost:3000 |
| API docs (Swagger) | http://localhost:8081/docs |
| Grafana | http://localhost:3001 |
| Prometheus | http://localhost:9090 |

In the UI: the **Dashboard** shows live counters and charts; **Alerts** lists every case with filters and a drill-down drawer; **Agent Ops** walks each agent's output and exposes **Approve/Reject** on pending cases; **System Health** shows every container's status.

---

## mTLS demo (Phase 7 highlight)

The approve/reject actions — the human-approval gate for destructive remediation — require a client certificate at the gateway. Reads, the dashboard, and Grafana stay open over plain TLS.

**In the terminal:**

```bash
# read works with no client cert
curl --cacert infrastructure/pki/ca.crt https://localhost/api/v1/health

# approving WITHOUT a client cert is blocked at the gateway
curl --cacert infrastructure/pki/ca.crt -X POST \
  https://localhost/api/v1/cases/<case_id>/approve            # -> 403

# WITH the analyst client cert it succeeds
curl --cacert infrastructure/pki/ca.crt \
  --cert infrastructure/pki/analyst.crt --key infrastructure/pki/analyst.key \
  -X POST https://localhost/api/v1/cases/<case_id>/approve    # -> 200
```

Or run the scripted demo (sends alice + bob, then proves the gate on a real pending case):

```bash
bash tests/demo_attack.sh
```

**In the browser:** open `https://localhost` and check the header badge — **"mTLS: no cert"** (amber) means approvals will be blocked. Import `infrastructure/pki/analyst.p12` (password `analyst`) into your browser's personal certificates, reload, and select the cert; the badge turns green (**"mTLS: analyst"**) and Approve/Reject now succeed. Trying to approve without it shows a red *"Blocked by mTLS"* banner. (Tip: use two browser profiles — one with the cert, one without — for a clean side-by-side.)

---

## Ports

| Service | Port | Notes |
|---|---|---|
| Gateway (HTTPS) | 443 / 80 | mTLS edge — the secure entrypoint |
| UI (nginx) | 3000 | Docker build of the dashboard |
| UI (Vite dev) | 5173 | `npm run dev`, proxies to the API |
| Ingestion API | 8000 | Wazuh webhook + health |
| Read API | 8081 | Powers the UI; docs at `/docs` |
| Grafana | 3001 | Also embeddable at `/grafana/` |
| Prometheus | 9090 | Metrics scraper |
| Worker metrics | 9100 | Prometheus exporter |
| cAdvisor | 8082 | Container metrics |
| Qdrant | 6333 / 6334 | Vector store REST / gRPC |
| Redis | 6380 | Host port (container 6379) |
| MongoDB | 27018 | Host port (container 27017) |

---

## Everyday operations

**Run the UI in hot-reload dev mode** (needs Node; proxies `/api` to `:8081`):

```bash
cd frontend && npm install && npm run dev    # http://localhost:5173
```

**Reset the case data to a clean slate:**

```bash
docker exec soc-mongodb mongosh --quiet --eval "db=db.getSiblingDB('soc_platform'); db.cases.deleteMany({}); db.recent_alerts.deleteMany({}); print('cleared')"
```

**Tail the pipeline worker:**

```bash
docker logs -f soc-worker
```

**Stop / tear down:**

```bash
docker compose down            # stop; keep data volumes
docker compose down -v         # also wipe redis/mongo/qdrant/grafana volumes
```

---

## Troubleshooting

- **Cases stuck before `reporting`, or verdict `unverified`** — the agents hit Groq rate limits and exhausted retries. Send fewer alerts at once, or use a higher Groq tier.
- **`otx_reputation: null` for a public IP** — OTX can be slow for heavily-referenced IPs; the first lookup per IP is cached, and internal `10.0.0.x` IPs are intentionally skipped.
- **Gateway returns 502** — a backend was recreated and the gateway hasn't re-resolved it yet (auto-heals within ~30s), or the container is down. Check `docker compose ps` and `docker logs soc-gateway`.
- **UI shows no data** — confirm the API is healthy (`curl http://localhost:8081/api/v1/health`) and that you've sent alerts (step 5).
- **Worker shows "down" in System Health** — it refreshes a Redis heartbeat each loop; check `docker logs soc-worker`.

Deferred production-hardening items are tracked in `docs/production_todo.md`.
