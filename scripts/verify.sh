#!/usr/bin/env bash
# Verify SLSA provenance + every scan attestation for one image digest.
# Writes ONLY verified payloads into $EV (default evidence/). Never exits non-zero on a failed
# verification: absence of a verified file is itself the evidence OPA uses to reject.
# usage: scripts/verify.sh sha256:<digest>
set -uo pipefail
DIGEST="${1:?sha256:digest}"
REPO="${REPO:-rajumandala/slsa-pipeline-lab}"
IMAGE="ghcr.io/$REPO"
EV="${EV:-evidence}"
ISSUER="https://token.actions.githubusercontent.com"
SCAN_ID="https://github.com/$REPO/.github/workflows/build.yml@refs/heads/main"
mkdir -p "$EV"; rm -f "$EV"/*.json "$EV"/verify.log
log() { echo "$*" | tee -a "$EV/verify.log"; }

# --- SLSA provenance (checks builder identity, source repo, branch) ---
if slsa-verifier verify-image "$IMAGE@$DIGEST" \
     --source-uri "github.com/$REPO" --source-branch main \
     --print-provenance > "$EV/provenance.json" 2>> "$EV/verify.log"; then
  log "PASS provenance"
else
  rm -f "$EV/provenance.json"
  # distinguish "missing" from "present but invalid"
  if cosign download attestation --predicate-type https://slsa.dev/provenance/v0.2 "$IMAGE@$DIGEST" 2>/dev/null | grep -q payload \
     || cosign download attestation --predicate-type https://slsa.dev/provenance/v1 "$IMAGE@$DIGEST" 2>/dev/null | grep -q payload; then
    echo '{"invalid": true}' > "$EV/provenance.invalid.json"; log "FAIL provenance (present but did not verify)"
  else
    log "FAIL provenance (missing)"
  fi
fi

# --- scan attestations, each must be signed by build.yml on main in this repo ---
for kind in sast sca secrets; do
  if cosign verify-attestation --type "https://slsa-pipeline-lab/attestations/${kind}/v1" \
       --certificate-identity "$SCAN_ID" --certificate-oidc-issuer "$ISSUER" \
       --certificate-github-workflow-repository "$REPO" \
       "$IMAGE@$DIGEST" > "$EV/${kind}.dsse.jsonl" 2>> "$EV/verify.log"; then
    log "PASS $kind attestation"
  else
    rm -f "$EV/${kind}.dsse.jsonl"; log "FAIL $kind attestation"
  fi
done
exit 0
