# Agentic AI SOC Platform — Full Project Plan

## 1. What this project is

A Security Operations Center (SOC) automation platform that ingests real security alerts from Wazuh (SIEM), and instead of dumping them into a queue for a human analyst to manually triage, runs each alert through a sequential pipeline of LLM-powered agents (built with LangGraph) that investigate, correlate, verify, and — where appropriate — recommend or execute a response, with a human approval gate before anything destructive happens.

This is not a machine-learning project. There is no trained model anywhere in this system. The "intelligence" comes entirely from agentic reasoning — an LLM (via Groq + Llama 3.3, same as your HPE project) that calls tools, retrieves grounding context from a RAG knowledge base, and reasons step by step, the same way a junior-to-mid SOC analyst would.

**One-line pitch:** "I built a SOAR-style platform where a chain of LangGraph agents triages, investigates, and responds to real Wazuh security alerts — grounded in MITRE ATT&CK via RAG, with a dedicated agent that checks the reasoning for hallucination before any action executes."

---

## 2. Why this project, and what gap it fills

You already have:
- **HPE AIOps platform** — agentic AI (LangGraph, RAG, Airflow, Docker) applied to *infrastructure remediation*
- **IEEE Access papers** — deep ML/CV research (AMR, IV fluid monitoring)

This project fills the one gap: **agentic AI applied to the security domain**, with a genuine, demoable cryptography component (TLS client certificate authentication) alongside it. Together, your three artifacts say: you can apply the same agentic pattern to different real-world problem domains, you understand applied cryptography (not just "we used HTTPS"), and you have depth in both research (papers) and engineering (working systems).

---

## 3. Full architecture — layer by layer

### Layer 1: SIEM Source
**Wazuh**, installed via Docker, monitoring a Linux VM (or another Docker container acting as a monitored host). Wazuh detects real security events — failed SSH logins, privilege escalation, file integrity changes — and fires alerts.

### Layer 2: Ingestion Layer
- **NGINX** — reverse proxy / entry point. In the implemented scope, this is also where TLS client certificate verification happens on admin/analyst routes (your cryptography component).
- **Ingestion Service (FastAPI)** — receives Wazuh's webhook, validates an auth token, parses the Wazuh JSON alert into your internal schema.
- **Redis Queue** — holds incoming normalized alerts, decoupling ingestion speed from agent processing speed.
- **Dead Letter Queue** — a second Redis list. Any alert that fails to parse or process correctly goes here instead of vanishing silently. Monitored by Prometheus.

### Layer 3: Correlation Engine (rule-based, no ML)
Sits between the Redis Queue and the Enrichment Engine. Looks at the last 15–30 minutes of alerts and checks for 2–3 hand-written correlation rules:
- Same IP + 3 or more failed logins in a 5-minute window
- Same host + failed/successful login followed by a privilege escalation event within 10 minutes
- Same user + access pattern deviating sharply from their recent history

Recent alerts for matching purposes are cached in MongoDB with a short TTL. Output is a `correlation_context` object attached to the alert — e.g., `{"related_alerts": 4, "pattern_matched": "brute_force_then_login", "time_window_minutes": 8}` — which gets passed forward instead of the agent seeing the alert in isolation.

### Layer 4: Enrichment Engine
Three parallel lookups, all attached to the alert before it reaches the agentic layer:
- **Threat intel enrichment** — AlienVault OTX API call on the source IP/domain, returns reputation data (known malicious, seen in threat feeds, etc.)
- **Asset context lookup** — host/user criticality (can be a simple hardcoded mapping for the demo — e.g., `prod-db-01` = critical, `dev-vm-03` = low)
- **Historical lookup** — MongoDB query for past cases involving this IP or user, giving the agent baseline context ("this user has never triggered an alert before" vs. "this IP has 12 prior flagged cases")

### Layer 5: Agentic Layer (LangGraph sequential pipeline)
This is the centerpiece. Full role breakdown in Section 4 below.

### Layer 6: RAG Knowledge Layer
- **Vector store:** ChromaDB
- **Corpus 1 — MITRE ATT&CK technique corpus:** 6–8 hand-picked techniques relevant to insider threat / common attack patterns (T1078 Valid Accounts, T1110 Brute Force, T1548 Privilege Escalation Abuse, T1048 Exfiltration, T1105 Ingress Tool Transfer, T1531 Account Access Removal, T1485 Data Destruction, T1083 File/Directory Discovery)
- **Corpus 2 — Remediation runbook library:** short, structured runbooks per alert type ("SSH brute force → block IP, lock account, notify")
- **Corpus 3 — Past resolved incident cases:** grows over time as analysts give feedback; this is your one "learning" mechanism, achieved via context retrieval, not model retraining

The Investigation agent queries this store to ground its findings in a named MITRE technique instead of just saying "this looks suspicious." The Remediation agent queries it to select the matching runbook.

### Layer 7: Output & Observability
- **MongoDB** — one document per case (`cases` collection), accumulating evidence, verdict, remediation action, and report as nested fields as the pipeline progresses
- **Prometheus** — scrapes metrics independently from every service: queue depth, processing latency, alerts/minute, agent error rate, DLQ size
- **Grafana** — SOC dashboard, fed by both MongoDB (case data) and Prometheus (system health) as two independent, parallel sources
- **Slack** — webhook notification for high-severity cases

### Layer 8: Feedback Loop
An analyst reviews a case (via Grafana or Slack), confirms or corrects the agent's verdict. That correction is written back onto the case document in MongoDB, and separately appended to the "past resolved cases" RAG collection — so the next similar alert retrieves this analyst-corrected case as grounding context. No model weights change; the system "learns" purely through accumulating better retrieval context.

---

## 4. Agentic layer — detailed role of every agent

The pipeline is **sequential**, not parallel — each agent's output becomes the next agent's input, closely mirroring how a real Tier 1 → Tier 2 → Tier 3 SOC escalation works. This is also the simplest pattern to build, debug, and demo in a short timeframe.

### Dispatcher Agent
**Not an LLM call.** Pure logic. Receives the enriched + correlated alert, creates a new case document in MongoDB with a unique case ID, and initializes the pipeline state (LangGraph's state object). Think of this as the "intake desk" — no reasoning happens here, just setup.

### Triage Agent
**First LLM call.** Reads the raw alert plus enrichment data (Wazuh rule level, asset criticality, OTX reputation) and does two things: classifies the alert type (auth failure, privilege escalation, file integrity violation, network anomaly, data access anomaly) and assigns an initial severity score. This is a fast, relatively shallow classification step — it doesn't investigate deeply yet, it just decides "what kind of thing is this and how urgent does it look on the surface."

### Investigation Agent
**The core reasoning agent, uses tool calling.** This is where the actual detective work happens. Given the classified alert, it decides which tools it needs and calls them in sequence:
- `get_login_history(user_or_ip)` — pulls recent login attempts from MongoDB
- `check_user_baseline(user)` — compares this behavior against the user's typical pattern
- `get_related_alerts(ip_or_user, window)` — reads the correlation_context object, expands on it if needed
- `query_rag(evidence_summary)` — retrieves matching MITRE ATT&CK techniques from ChromaDB based on the pattern of evidence gathered

It synthesizes all of this into a structured evidence report: what happened, in what order, how it compares to baseline, and which MITRE techniques it resembles. This agent is the one doing genuine multi-step reasoning — it decides what to investigate next based on what it's already found, which is what justifies using an agent here instead of a fixed rule chain.

### Decision Agent
**LLM call, can be folded into Investigation agent's final output if you're short on time.** Reads the Investigation agent's evidence report and makes a binary call: true positive or false positive. Also assigns a final severity (which may differ from Triage's initial guess, now that real evidence has been gathered).

### Verification Agent (Hallucination Guard)
**This is your differentiator — build this even if you cut other agents.** Runs only when Decision says "true positive." Its entire job is to independently double-check the Decision agent's conclusion before anything is allowed to act on it:
- Does the evidence actually support this conclusion, or did the model overreach?
- Is the cited MITRE technique actually a good match for the evidence, or was it retrieved but misapplied?
- Does this violate any policy rule (e.g., "never auto-remediate against a case where the affected user is `admin`")?

If it finds the conclusion ungrounded or unsafe, the case routes straight to the Reporting agent — flagged as "rejected by verification" — and never reaches Remediation. This is your direct answer to "how do you stop an LLM agent from hallucinating a wrong action," backed by an actual pipeline node rather than a design principle you just talk about.

### Remediation Agent
**Only runs on verified true positives.** Queries the RAG runbook library for the matching response procedure, and drafts a specific action — block an IP, disable a user account, isolate a host. It does not execute destructive actions directly; it proposes them.

### Human Approval Gate
**Not an LLM call, a pipeline pause.** For the demo, this can be as simple as a flag in MongoDB that a "Slack approve/reject" webhook flips, or even a manual toggle in a lightweight UI. The point is architectural: nothing destructive executes without a human in the loop. Non-destructive actions (like tagging a case for review) can skip this gate.

### Reporting Agent
**Always runs, regardless of outcome.** Writes the final structured incident report: case summary, severity, evidence chain, matched MITRE techniques (if any), verdict, and (if applicable) the remediation action taken and its approval status. Every alert — true or false positive, verified or rejected — ends up with a documented reasoning trail in MongoDB. This matters for the demo because it means your Grafana dashboard has something to show for every single alert, not just the interesting ones.

---

## 5. Full data flow, step by step

1. Wazuh detects a security event on a monitored host (e.g., repeated failed SSH logins)
2. Wazuh sends the alert to the platform via webhook/API
3. NGINX receives the request (in the implemented build: also verifies TLS client cert if hitting an admin route; the Wazuh webhook itself is a standard authenticated endpoint)
4. Ingestion Service (FastAPI) validates the auth token and normalizes the Wazuh JSON into your internal alert schema
5. Alert is pushed onto the Redis queue (malformed/failed alerts route to the Dead Letter Queue instead)
6. Correlation Engine consumes the alert, checks recent MongoDB alert history for matching IP/user/host patterns, attaches a `correlation_context` object
7. Enrichment Engine attaches AlienVault OTX reputation data, asset criticality, and historical case lookup
8. Dispatcher Agent creates a case document in MongoDB and initializes the LangGraph pipeline state
9. Triage Agent classifies alert type and assigns an initial severity
10. Investigation Agent gathers evidence via tool calls (login history, baseline check, related alerts) while querying the RAG store for matching MITRE ATT&CK context
11. Decision Agent determines true positive or false positive based on the gathered evidence
12. **If false positive:** case routes directly to the Reporting Agent
13. **If true positive:** case routes to the Verification Agent, which independently re-checks the evidence and conclusion
14. **If Verification rejects the conclusion:** case routes to Reporting Agent, flagged as rejected
15. **If Verification confirms:** case routes to the Remediation Agent, which selects a runbook (via RAG) and drafts a response action
16. Destructive actions pause at the Human Approval Gate; non-destructive actions proceed directly
17. Reporting Agent writes the final structured summary regardless of path taken
18. Case document is finalized in MongoDB; Grafana dashboard updates; high-severity cases trigger a Slack notification
19. An analyst reviews the case (via Grafana or Slack), confirms or corrects the verdict
20. The correction is written back onto the case document and separately appended to the "past resolved cases" RAG collection, enriching context for future investigations

---

## 6. Tech stack summary

| Layer | Technology |
|---|---|
| SIEM | Wazuh (Docker) |
| Reverse proxy / TLS | NGINX, self-signed CA (OpenSSL) for client cert auth |
| Backend API | FastAPI |
| Queue | Redis (+ Dead Letter Queue) |
| Correlation | Custom rule-based logic (Python), MongoDB short-TTL cache |
| Enrichment | AlienVault OTX API, hardcoded asset criticality map, MongoDB lookup |
| Agent orchestration | LangGraph |
| LLM | Groq API — Llama 3.3 70B |
| RAG / vector store | ChromaDB |
| Database | MongoDB (one document per case) |
| Metrics | Prometheus |
| Dashboard | Grafana |
| Notifications | Slack webhook |
| Deployment | Docker Compose, single cloud VM (AWS/GCP free tier) |

---

## 7. Recommended build order (5-day sprint)

**Day 1** — Skeleton first: Docker Compose with empty FastAPI/Redis/MongoDB talking to each other via dummy payloads. Then wire up real Wazuh ingestion — webhook receiving real alerts, landing in Redis, with the Dead Letter Queue in place.

**Day 2** — Correlation engine (2–3 rules, MongoDB-backed recent alert cache) in the morning; Enrichment engine (OTX call, asset lookup, historical lookup) in the afternoon. Checkpoint: an alert entering the agentic layer now carries full context.

**Day 3–4** — Agentic layer, built and tested one agent at a time: Dispatcher → Triage → Investigation (add tool calls one at a time) → RAG setup and wiring → Decision → Verification (don't skip this) → Remediation + Approval Gate → Reporting. Run the full pipeline end to end by end of Day 4.

**Day 5 (morning)** — Prometheus + Grafana wiring (3–4 panels: alert volume, severity breakdown, case status, verdict distribution), feedback loop wiring.

**Day 5 (afternoon)** — mTLS: self-signed CA, NGINX client cert requirement on the admin route, demo the reject/accept behavior.

**Whatever's left** — Write and rehearse the attack demo script; run it 3–4 times until smooth.

---

## 8. Demo script

**Setup:** two terminal windows or two simulated identities — "Alice" (normal user) and "Bob" (attacker).

1. Trigger a normal event as Alice — e.g., a single failed login followed by a successful one. Watch it flow through the pipeline: Triage classifies it as low severity, Investigation finds nothing unusual in her baseline, Decision marks it false positive, Reporting closes it out. Grafana shows it logged as routine.

2. Run the Bob attack script — repeated failed SSH logins from a new IP, followed by a successful login, followed by a simulated privilege escalation event. Watch the Correlation Engine catch the pattern (`brute_force_then_login`), the Investigation agent pull this into its evidence, retrieve T1110 (Brute Force) and T1548 (Privilege Escalation Abuse) from the RAG store, Decision mark it true positive, Verification independently confirm the evidence supports it, Remediation propose blocking the IP and locking the account, and the case pause at the Human Approval Gate.

3. Show the Grafana dashboard updating live throughout — alert volume spike, severity breakdown shifting, the new case appearing in the incident feed.

4. Approve the remediation action via Slack (or your approval mechanism) and show the case closing out with a full structured report — evidence chain, matched MITRE techniques, action taken.

5. Optionally: show a case where Verification *rejects* a Decision agent's conclusion (deliberately engineer a borderline case), demonstrating the hallucination guard actually functioning, not just existing as a diagram box.

6. Show the mTLS piece separately: `curl` the admin dashboard route without a client cert → rejected. `curl --cert admin.crt --key admin.key` → accepted.

---

## 9. Interview talking points

**"Why did this need an agent instead of just rules?"**
Individual alerts are low-signal in isolation. Correlation catches simple time-windowed patterns, but the Investigation agent's job — deciding what additional evidence to gather based on what it's already found, and grounding its conclusion in a specific MITRE ATT&CK technique rather than a generic "suspicious" label — is genuinely multi-step, context-dependent reasoning. A fixed rule tree would need every branch enumerated in advance; the agent adapts its investigation path per case.

**"How do you prevent the agent from hallucinating an incorrect action?"**
There's a dedicated Verification agent that runs after any true-positive decision, before Remediation is ever reached. It independently re-checks whether the evidence actually supports the conclusion and whether the cited MITRE technique is a genuine match, not just a retrieved-but-misapplied result. If it can't confirm, the case is routed to reporting instead of action — nothing destructive executes on an unverified conclusion.

**"Walk me through the correlation engine — is that ML?"**
No — it's deliberately rule-based. Time-windowed matching on IP/user/host plus 2–3 known sequence patterns (brute force → login → privilege escalation). I chose rule-based over an ML/clustering approach because the goal was a reliable, explainable signal in a short build window; an ML-based correlation model would need labeled training data and validation that wasn't feasible in the timeframe. It's also easily extensible — the same output slot could later be replaced with an ML-based version without changing anything downstream.

**"What's the human approval gate for?"**
Any remediation action classified as destructive (blocking an IP, disabling an account, isolating a host) pauses for explicit human approval before executing. Non-destructive actions (tagging, escalating severity) can proceed autonomously. This reflects how real incident response actually works — automation accelerates investigation and drafts the response, but a human stays accountable for anything with real-world consequences.

**"Tell me about the cryptography component."**
I implemented TLS client certificate authentication at the NGINX edge — a self-signed CA issues a server cert for NGINX and a client cert for admin/analyst access, and NGINX rejects any request to the admin dashboard that doesn't present a valid client certificate. At production scale, this would extend to full mutual TLS between every internal service, typically automated via a private CA (Step CA or HashiCorp Vault PKI) issuing short-lived, auto-rotated certificates to each container on startup — often implemented transparently via a service mesh sidecar (Istio/Linkerd) rather than hand-configuring each service.

**"Why MongoDB and not a relational database?"**
Each case is naturally a single cohesive unit that gets built up incrementally by different agents — evidence, verdict, remediation, and report all nest inside one case document rather than needing joins across separate tables. Given the 5-day build window, MongoDB's schema flexibility also meant I could adjust what each agent outputs without running migrations mid-build.

**"What would you build next if you had more time?"**
Full inter-service mTLS via a service mesh, an ML-based correlation layer (clustering or sequence models) to catch attack patterns beyond the hand-written rules, and a proper analyst-facing frontend rather than driving the demo through Grafana and Slack alone.

---

## 10. What this demonstrates on your resume

Alongside your HPE AIOps platform (agentic AI applied to infrastructure remediation) and your IEEE Access research (deep ML/CV), this project demonstrates: agentic AI applied to the security domain, grounded reasoning via RAG and MITRE ATT&CK, a real safeguard against LLM hallucination in an autonomous pipeline, applied cryptography (PKI/TLS client certificates) with an honest understanding of how it would scale to full production mTLS, and full-stack DevOps competency (Docker Compose, Prometheus, Grafana, cloud deployment). It is the one project in your portfolio that speaks directly to security engineering, SOC automation, and DevSecOps hiring profiles — the domain your other two projects don't cover.
