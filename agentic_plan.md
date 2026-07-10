 Phase 5 — Agentic Layer (LangGraph)

 Context

 The pipeline currently runs ingestion → Redis → worker → correlation → enrichment → case doc in Mongo (Phases 0–3,
 all verified working). The next phase is the centerpiece: a sequential LangGraph agent pipeline that triages,
 investigates, verifies, and drafts remediation for each enriched alert, writing its reasoning into the same
 CaseDocument.

 We're building agents before RAG (Phase 4). That works because only 2 of the agents' tools touch RAG
 (query_mitre_attack, query_runbooks) — those get stubbed behind the exact interface a future ChromaDB RAGStore will
 satisfy, so Phase 4 swaps them in with zero agent changes.

 Firm decisions: real ChatGroq + Llama 3.3 70B (user is adding SOC_GROQ_API_KEY); Decision agent folded into
 Investigation's output; RAG tools stubbed; pipeline runs inside the existing worker process (no new service).

 Key technical constraint (drives the whole design)

 ChatGroq's .with_structured_output() and .bind_tools() compete for the same tool-calling channel — a model turn
 can't reliably both call investigation tools and emit a forced Pydantic schema. Llama 3.3 degrades when juggling
 both.

 Solution: no LLM call ever needs both channels.
 - Triage / Verification / Remediation / Reporting → single .with_structured_output(Model, method="function_calling")
 call, nothing else bound.
 - Investigation → two-phase: Phase A runs a prescribed tool sequence as ordinary async Python (no LLM tool-calling
 channel used at all); Phase B is a pure .with_structured_output(InvestigationOutput) synthesis call. This sidesteps
 the conflict structurally and avoids ReAct-loop unreliability/rate-limit cost.

 Files to create under agents/

 All match house style: async, logging.getLogger("soc.agents.*"), config-driven, graceful failure isolation (mirror
 enrichment/engine.py and correlation/engine.py). All output Pydantic models already exist in common/models.py.

 File: llm.py
 LLM?: —
 Output model: —
 Role: get_llm(temperature=0.0) → ChatGroq factory; with_retry() async backoff honoring Retry-After (we set
   max_retries=0 and drive retries ourselves).
 ────────────────────────────────────────
 File: tools.py
 LLM?: —
 Output model: —
 Role: get_login_history, check_user_baseline, get_correlation_context (Mongo/state reads) + RAG stubs
   query_mitre_attack, query_runbooks (hardcoded 8 MITRE techniques + runbooks; signatures match future
   RAGStore.query).
 ────────────────────────────────────────
 File: state.py
 LLM?: —
 Output model: —
 Role: PipelineState TypedDict (total=False); holds Pydantic objects directly.
 ────────────────────────────────────────
 File: dispatcher.py
 LLM?: no
 Output model: —
 Role: Intake; sets current_stage, status→TRIAGING. Pure logic.
 ────────────────────────────────────────
 File: triage.py
 LLM?: yes
 Output model: TriageOutput
 Role: Shallow classification: alert_type, initial_severity (1–10). Fed rule level, asset criticality, OTX,
   correlation pattern.
 ────────────────────────────────────────
 File: investigation.py
 LLM?: yes
 Output model: InvestigationOutput
 Role: Two-phase (above). Folds in verdict + confidence_score + final_severity.
 ────────────────────────────────────────
 File: verification.py
 LLM?: yes
 Output model: VerificationOutput
 Role: Hallucination guard (differentiator). Deterministic policy gate + independent LLM re-check. TP only.
 ────────────────────────────────────────
 File: remediation.py
 LLM?: yes
 Output model: RemediationOutput
 Role: Selects runbook (stub), drafts specific actions with is_destructive. Verified TP only. Proposes, never
   executes.
 ────────────────────────────────────────
 File: approval.py
 LLM?: no
 Output model: —
 Role: Gate: destructive → PENDING_APPROVAL + Mongo flag; non-destructive → auto-approve. Never blocks the graph. #
   TODO: notify_slack seam.
 ────────────────────────────────────────
 File: reporting.py
 LLM?: yes
 Output model: IncidentReport
 Role: Always runs; analyst-facing narrative; finalizes case status.
 ────────────────────────────────────────
 File: pipeline.py
 LLM?: —
 Output model: —
 Role: build_pipeline() (compiled once) + run_pipeline(enriched, case_id) + the two router functions.

 LangGraph wiring (pipeline.py)

 START → dispatcher → triage → investigation → verdict_router
 verdict_router:  FALSE_POSITIVE → reporting
                  TRUE_POSITIVE  → verification
 verification → verified_router
 verified_router: verified      → remediation
                  rejected       → reporting   (report.verdict = REJECTED)
 remediation → approval → reporting → END
 - verdict_router: any non-TRUE_POSITIVE (incl. UNVERIFIED fallback) → reporting. Never proceeds to remediation on
 ambiguity.
 - Nodes are async def node(state) -> dict returning only their delta (LangGraph last-write-wins per key; no custom
 reducers).
 - Each node does an incremental db.cases.update_one({case_id}, {"$set": {...}}) with model_dump(mode="json") at the
 write boundary (handles enums/datetimes; crash mid-pipeline leaves correct partial state + status). Reporting does
 the final consolidated write.

 Status transitions: dispatcher→TRIAGING, triage→INVESTIGATING, investigation→VERIFYING(TP)/reporting(FP),
 verification→REMEDIATING(verified)/reporting(rejected), approval→PENDING_APPROVAL(destructive),
 reporting→PENDING_APPROVAL(gated) or CLOSED.

 Investigation two-phase detail

 Phase A (code, no LLM): call in order — get_correlation_context(state) → get_login_history(user, source_ip) →
 check_user_baseline(user) → build evidence_summary → query_mitre_attack(evidence_summary). Assemble evidence_bundle
 dict into state.
 - get_login_history → recent_alerts matching user/IP in window; returns {failed_logins, successful_logins,
 first_seen, last_seen, events[]} (counts derived from event_classes).
 - check_user_baseline → prior cases for user + recent_alerts volume; returns {prior_case_count, known_user,
 deviation}.

 Phase B (1 LLM call): .with_structured_output(InvestigationOutput) over triage + evidence_bundle → timeline,
 baseline_comparison, matched_mitre_techniques, verdict, confidence, final_severity.

 Verification (the guard)

 1. Deterministic policy pre-check (code): if alert.user in settings.agent_no_autoremediate_users (new config,
 default {"admin","root"}) → force verified=False, policy_check="privileged account requires human review".
 2. Independent LLM check: given investigation output + raw evidence_bundle only (not its reasoning text, to keep it
 independent) → evidence_check, mitre_check, verified, rejection_reason.
 3. verified = deterministic_ok AND llm_verified — either can veto.

 Dependencies & integration

 - common/config.py — add: agent_no_autoremediate_users: set[str] = {"admin","root"}, agent_llm_temperature: float =
 0.0, agent_llm_max_tokens: int = 1024, agent_max_retries: int = 5.
 - common/requirements.txt — add langgraph>=0.2.60,<0.3, langchain-core>=0.3.30,<0.4, langchain-groq>=0.2.3,<0.3
 (verify resolve against pydantic>=2.7,<3).
 - common/Dockerfile — add COPY agents/ /app/agents/.
 - common/worker.py process_alert() — after enrichment + case insert: build EnrichedAlert, await
 run_pipeline(enriched, case.case_id) wrapped in try/except (failure sets a terminal error status, worker continues).
 Build graph once at module import. Keep processing sequential (no cross-alert parallelism — correlation/history
 depend on insert order). Use ainvoke only.

 Build milestones (build + test each before the next)

 1. Foundation: llm.py + tools.py + deps + Dockerfile + config. Smoke-test
 get_llm().with_structured_output(TriageOutput).ainvoke(...) against real Groq.
 2. Simple nodes: state.py + dispatcher.py + triage.py — prove structured output works live.
 3. Investigation: two-phase agent + Mongo tools.
 4. Guard + response: verification.py + remediation.py + approval.py.
 5. Wire it: reporting.py + pipeline.py + worker integration.
 6. End-to-end: run alice + bob.

 Verification

 Rebuild worker (docker compose up -d --build worker), add SOC_GROQ_API_KEY to .env first.

 - Alice (python tests/send_alerts.py alice): → verdict=false_positive, routes straight to reporting, status=closed.
 No verification/remediation run.
 - Bob (python tests/send_alerts.py bob --count 5): correlation brute_force_then_login+priv-esc → investigation
 matches T1110+T1548, verdict=true_positive → verification confirms (user baduser, not admin/root) → remediation
 proposes block_ip/disable_account (destructive) → approval → status=pending_approval,
 report.approval_status=pending.
 - Guard demo: a bob-like case forced to user=admin → deterministic reject → routed to reporting flagged rejected
 (shows the guard firing).

 db.cases.find({"alert.user":"alice"}).sort({created_at:-1}).limit(1)   // report.verdict false_positive, status
 closed
 db.cases.find({"alert.user":"baduser"}).sort({created_at:-1}).limit(1) // status pending_approval,
 verification.verified true, remediation.proposed_actions non-empty

 Risks

 - Groq rate limits (~20+ calls per bob burst): with_retry backoff + temperature=0 + tight max_tokens; sequential
 worker serializes calls; optional min-interval between Groq calls if TPM hit.
 - Structured-output validity: wrap each structured call — retry once with a "return valid JSON" nudge, then
 safe-default (investigation → verdict=UNVERIFIED, which routes to reporting, never remediation). Never crash the
 worker.
 - Async: ainvoke only, all nodes async, graph built once, model_dump(mode="json") at Mongo boundaries.