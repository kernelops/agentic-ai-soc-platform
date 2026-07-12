#!/usr/bin/env bash
# =============================================================================
# Phase 7 — end-to-end demo with the mTLS gateway.
#
#   1. Alice: benign login (single fail then success)   -> false positive
#   2. Bob:   brute force -> login -> sudo priv-esc      -> true positive
#              -> destructive remediation -> PENDING APPROVAL
#   3. mTLS proof on the human-approval gate:
#         - approve WITHOUT a client cert   -> 403 (blocked at the gateway)
#         - approve WITH the analyst cert    -> 200 (approved)
#
# Prereqs:
#   - full stack up (docker compose up -d --build) incl. the gateway
#   - certs generated: bash infrastructure/pki/generate_certs.sh
#   - SOC_GROQ_API_KEY set so the agent pipeline runs
#
# Usage: bash tests/demo_attack.sh
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

GATEWAY="${GATEWAY:-https://localhost}"
PKI="infrastructure/pki"
CA="$PKI/ca.crt"
CERT="$PKI/analyst.crt"
KEY="$PKI/analyst.key"

line() { printf '%s\n' "----------------------------------------------------------------"; }

for f in "$CA" "$CERT" "$KEY"; do
  if [[ ! -f "$f" ]]; then
    echo "Missing $f — run: bash infrastructure/pki/generate_certs.sh"
    exit 1
  fi
done

CURL_TLS=(--cacert "$CA")

# Pre-flight: the gateway + API path must be reachable, or the poll below would
# silently look like "no pending case". Fail loudly instead.
if ! curl -fsS "${CURL_TLS[@]}" "$GATEWAY/api/v1/health" >/dev/null 2>&1; then
  echo "Gateway/API not reachable at $GATEWAY/api/v1/health"
  echo "  - is the gateway up?           docker compose ps gateway"
  echo "  - did backends just restart?   docker compose up -d --force-recreate gateway"
  exit 1
fi
echo "Gateway reachable at $GATEWAY (TLS OK)."

line
echo "[1/4] Sending ALICE (benign) — expect false positive"
line
python3 tests/send_alerts.py alice

line
echo "[2/4] Sending BOB (attack) — expect true positive -> pending approval"
line
python3 tests/send_alerts.py bob --count 3

line
echo "[3/4] Waiting for the agent pipeline to reach a pending-approval case..."
line
CID=""
for i in $(seq 1 30); do
  CID=$(curl -s "${CURL_TLS[@]}" "$GATEWAY/api/v1/cases?status=pending_approval&limit=1" \
    | python3 -c "import sys,json; items=json.load(sys.stdin).get('items',[]); print(items[0]['case_id'] if items else '')" 2>/dev/null || true)
  if [[ -n "$CID" ]]; then break; fi
  sleep 5
done

if [[ -z "$CID" ]]; then
  echo "No pending-approval case appeared. Check worker logs (Groq rate limits?)."
  exit 1
fi
echo "Pending-approval case: $CID"

line
echo "[4/4] mTLS proof on POST /api/v1/cases/$CID/approve"
line

echo -n "  Without client cert : "
code=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_TLS[@]}" \
  -X POST "$GATEWAY/api/v1/cases/$CID/approve" \
  -H "Content-Type: application/json" -d '{}' || true)
echo "HTTP $code $( [[ "$code" == "403" ]] && echo '(blocked as expected)' || echo '(UNEXPECTED)')"

echo -n "  With analyst cert   : "
code=$(curl -s -o /dev/null -w "%{http_code}" "${CURL_TLS[@]}" --cert "$CERT" --key "$KEY" \
  -X POST "$GATEWAY/api/v1/cases/$CID/approve" \
  -H "Content-Type: application/json" -d '{"note":"approved via mTLS demo"}' || true)
echo "HTTP $code $( [[ "$code" == "200" ]] && echo '(approved)' || echo '(UNEXPECTED)')"

line
echo "Done. The destructive-action gate is reachable only with a valid analyst"
echo "client certificate; reads and the dashboard remain open over TLS."
line
