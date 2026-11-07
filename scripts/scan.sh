#!/usr/bin/env bash
# Run SAST / SCA / secrets scans, write raw JSON + predicates to $OUT, then apply the OPA build gate.
# usage: scripts/scan.sh <image-ref>        (same script runs locally and in CI)
set -euo pipefail
IMAGE="${1:?image ref}"
OUT="${OUT:-scan-results}"
mkdir -p "$OUT"
HERE="$(cd "$(dirname "$0")" && pwd)"

# Every tool exits 0 on findings: pass/fail is the policy's job, not the tool's default.
semgrep scan --config p/python --config p/flask --metrics=off --quiet --json -o "$OUT/semgrep.json" app/ || true
test -s "$OUT/semgrep.json" || { echo "semgrep produced no output"; exit 2; }

trivy fs    --quiet --scanners vuln --format json -o "$OUT/trivy-fs.json" .
trivy image --quiet --scanners vuln --format json -o "$OUT/trivy-image.json" "$IMAGE"

if git rev-parse --git-dir >/dev/null 2>&1; then
  gitleaks git --no-banner --redact --exit-code 0 --report-format json --report-path "$OUT/gitleaks.json" .
else
  gitleaks dir --no-banner --redact --exit-code 0 --report-format json --report-path "$OUT/gitleaks.json" .
fi

python3 "$HERE/summarize.py" sast    "$(semgrep --version)"                       "$OUT/sast.json"    "$OUT/semgrep.json"
python3 "$HERE/summarize.py" sca     "$(trivy --version | awk 'NR==1{print $2}')" "$OUT/sca.json"     "$OUT/trivy-fs.json" "$OUT/trivy-image.json"
python3 "$HERE/summarize.py" secrets "$(gitleaks version)"                       "$OUT/secrets.json" "$OUT/gitleaks.json"

python3 -c 'import json,sys; o=sys.argv[1]; json.dump({k: json.load(open(f"{o}/{k}.json")) for k in ("sast","sca","secrets")}, open(f"{o}/summary.json","w"))' "$OUT"

DENY="$(opa eval --format raw -d policy/scan_gate.rego -d policy/thresholds.json -i "$OUT/summary.json" 'concat("\n", data.scan_gate.deny)')"
if [ -n "$DENY" ]; then
  echo "::error::Build gate FAILED"; echo "$DENY"; exit 1
fi
echo "Build gate passed"
