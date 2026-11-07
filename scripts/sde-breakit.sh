#!/usr/bin/env bash
# Break-it: a developer tries to mark T-SAST Complete. Runs an isolated mock (port 8001, temp DB)
# so the demo starts from a clean "Incomplete" state. Reconcile uses REAL cosign against GHCR.
# usage: scripts/sde-breakit.sh [good-digest]   (good digest enables the "legit CI update survives" step)
set -euo pipefail
cd "$(dirname "$0")/.."
GOOD="${1:-}"
TMP="$(mktemp -d)"; export MOCK_DB="$TMP/demo.db"
export MOCK_SDE_CI_TOKEN="ci-$RANDOM$RANDOM" MOCK_SDE_DEV_TOKEN="dev-$RANDOM$RANDOM" MOCK_CR_TOKEN="cr-$RANDOM$RANDOM"
.venv/bin/uvicorn mocks.main:app --port 8001 --log-level warning & PID=$!
trap 'kill $PID; rm -rf "$TMP"' EXIT
U=http://127.0.0.1:8001; until curl -fs $U/healthz >/dev/null; do sleep 0.3; done
show() { curl -s "$U/sde/countermeasures" | python3 -c 'import sys,json;[print("    ",r["id"],r["status"],"by",r["changed_by"],(r["digest"] or "")[:19]) for r in json.load(sys.stdin) if r["id"]=="T-SAST"]'; }
put() { curl -s -o /dev/null -w "     HTTP %{http_code}\n" -X PUT "$U/sde/countermeasures/T-SAST" -H "Authorization: Bearer $1" \
          -H 'Content-Type: application/json' -d "{\"status\":\"Complete\",\"note\":\"$2\",\"digest\":\"$3\"}"; }
FAKE="sha256:$(printf '1%.0s' $(seq 64))"

echo "== start";                                                   show
echo "== 1) developer token: PUT T-SAST=Complete  -> blocked";      put "$MOCK_SDE_DEV_TOKEN" "trust me" "$FAKE"; show
echo "== 2) developer edits the store directly    -> reverted"
python3 -c "import sqlite3,sys;c=sqlite3.connect(sys.argv[1]);c.execute(\"UPDATE cm SET status='Complete',changed_by='developer',note='manual edit' WHERE id='T-SAST'\");c.commit()" "$MOCK_DB"
show; echo "     reconcile:"; curl -s -X POST $U/sde/reconcile; echo; show
echo "== 3) leaked CI token + digest with no attestation -> reverted"
put "$MOCK_SDE_CI_TOKEN" "forged" "$FAKE"; show; echo "     reconcile:"; curl -s -X POST $U/sde/reconcile; echo; show
if [ -n "$GOOD" ]; then
  echo "== 4) CI token + real attested digest -> survives reconcile"
  put "$MOCK_SDE_CI_TOKEN" "release run" "$GOOD"; echo "     reconcile:"; curl -s -X POST $U/sde/reconcile; echo; show
fi
echo "== alerts"; curl -s $U/sde/alerts | python3 -c 'import sys,json;[print("    ",a["msg"][:150]) for a in json.load(sys.stdin)]'
