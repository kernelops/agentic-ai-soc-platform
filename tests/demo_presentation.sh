#!/usr/bin/env bash
# =============================================================================
# AI_SOC — guided presentation demo.
#
# Paced with pauses so you can narrate and switch to the dashboard between
# steps. Drives four scenarios end to end:
#   1. Benign login (Alice)            -> false positive, auto-closed
#   2. Brute-force intrusion (Bob)     -> true positive -> pending approval
#   3. Known-malicious source IP       -> live OTX threat intel
#   4. Human approval gate + mTLS      -> 403 without cert, 200 with cert
#
# Prereqs: full stack up, certs generated, RAG ingested, SOC_GROQ_API_KEY set.
# Open the UI at https://localhost (through the gateway) alongside this.
#
# Usage: bash tests/demo_presentation.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

GATEWAY="${GATEWAY:-https://localhost}"
PKI="infrastructure/pki"
CA="$PKI/ca.crt"; CERT="$PKI/analyst.crt"; KEY="$PKI/analyst.key"
TLS=(--cacert "$CA")

bold=$'\e[1m'; dim=$'\e[2m'; grn=$'\e[32m'; red=$'\e[31m'; cyn=$'\e[36m'; rst=$'\e[0m'
say()   { echo; echo "${bold}${cyn}=== $* ===${rst}"; }
note()  { echo "  $*"; }
pause() { echo; read -rp "${dim}  ▸ press Enter to continue…${rst}" _; echo; }

for f in "$CA" "$CERT" "$KEY"; do
  [[ -f "$f" ]] || { echo "Missing $f — run: bash infrastructure/pki/generate_certs.sh"; exit 1; }
done
if ! curl -fsS "${TLS[@]}" "$GATEWAY/api/v1/health" >/dev/null 2>&1; then
  echo "${red}Gateway not reachable at $GATEWAY${rst} — is the stack up? (docker compose ps)"
  exit 1
fi

clear
cat <<BANNER
${bold}AI_SOC — Agentic AI Security Operations Center${rst}

  Alert  ->  Ingestion  ->  Redis  ->  Worker pipeline:
     • Correlation   rules link related alerts (brute force, then-login, priv-esc)
     • Enrichment    OTX reputation + asset criticality + case history
     • Agents (LLM)  triage -> investigate -> verify -> remediate -> approve -> report
  ->  MongoDB case  ->  API  ->  Dashboard UI
  All fronted by a TLS/mTLS gateway; metrics in Prometheus/Grafana.
BANNER
pause

# ---------------------------------------------------------------------------
say "Scenario 1 — Benign login (Alice)"
note "One failed SSH login then a success, from a normal user on a normal host."
note "Expect: the agents rule it a ${grn}FALSE POSITIVE${rst} and auto-close it — no analyst noise."
pause
python3 tests/send_alerts.py alice
note "→ UI: Alerts shows the case; open it in Agent Ops → verdict false_positive, status closed."
pause

# ---------------------------------------------------------------------------
say "Scenario 2 — Brute-force intrusion (Bob)  [the main event]"
note "3 failed logins from one attacker IP → a successful login → first-time sudo."
note "Expect: correlation links them (brute_force → brute_force_then_login → priv_esc_after_login),"
note "agents rule ${red}TRUE POSITIVE${rst}, match MITRE ${bold}T1110 + T1548${rst}, propose destructive"
note "remediation (block IP / disable account / isolate host), and ${bold}PAUSE for approval${rst}."
pause
python3 tests/send_alerts.py bob --count 3
echo
note "→ Walk the tabs while the agents run (~1 min, watch the worker via 'docker logs -f soc-worker'):"
note "   Dashboard   — counters + alert-volume tick up"
note "   Correlation — pattern chips; open the cluster to show the linked alerts"
note "   Enrichment  — asset criticality = critical (prod-db-01)"
note "   Agent Ops   — open the case → full agent chain, verdict, MITRE, remediation, PENDING APPROVAL"
pause

# ---------------------------------------------------------------------------
say "Scenario 3 — Known-malicious source (live threat intel)"
note "Same attack pattern, but from a real public IP flagged in AlienVault OTX."
pause
python3 tests/send_alerts.py bob --srcip 185.220.101.1
note "→ Enrichment tab: the OTX badge lights up (malicious, pulse count, country)."
pause

# ---------------------------------------------------------------------------
say "Scenario 4 — Human approval gate, secured with mTLS"
note "Destructive remediation only executes if an analyst with a client certificate approves it."
echo
note "Finding a case that's pending approval…"
CID=""
for _ in $(seq 1 24); do
  CID=$(curl -s "${TLS[@]}" "$GATEWAY/api/v1/cases?status=pending_approval&limit=1" \
    | python3 -c "import sys,json;i=json.load(sys.stdin).get('items',[]);print(i[0]['case_id'] if i else '')" 2>/dev/null || true)
  [[ -n "$CID" ]] && break
  sleep 5
done
if [[ -z "$CID" ]]; then
  note "${red}No pending-approval case yet${rst} (agents may still be running / rate-limited). Re-run this step later."
else
  note "Pending case: ${bold}$CID${rst}"
  pause
  echo "  ${bold}(a) Approve WITHOUT a client certificate${rst} — the gateway should block it:"
  code=$(curl -s -o /dev/null -w "%{http_code}" "${TLS[@]}" -X POST \
    "$GATEWAY/api/v1/cases/$CID/approve" -H "Content-Type: application/json" -d '{}' || true)
  echo "      → HTTP $code $([[ "$code" == "403" ]] && echo "${red}BLOCKED${rst}" || echo "(unexpected)")"
  echo
  echo "  ${bold}(b) Approve WITH the analyst certificate${rst} — authorized:"
  code=$(curl -s -o /dev/null -w "%{http_code}" "${TLS[@]}" --cert "$CERT" --key "$KEY" -X POST \
    "$GATEWAY/api/v1/cases/$CID/approve" -H "Content-Type: application/json" -d '{"note":"approved in demo"}' || true)
  echo "      → HTTP $code $([[ "$code" == "200" ]] && echo "${grn}APPROVED${rst}" || echo "(unexpected)")"
  echo
  note "→ In the browser (https://localhost): header badge shows the mTLS status;"
  note "  approving without the cert shows a red 'Blocked by mTLS' banner, with it the case closes."
fi
pause

say "Demo complete"
note "Recap: benign auto-closed, real attack fully investigated & MITRE-mapped, threat intel applied,"
note "and the only destructive step gated behind a certificate-authenticated human approval."
