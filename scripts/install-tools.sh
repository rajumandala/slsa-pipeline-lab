#!/usr/bin/env bash
# Install pinned, checksum-verified lab tools into ~/.local/bin (Linux amd64).
# macOS: `brew install cosign slsa-verifier opa trivy gitleaks cloudflared kyverno semgrep kind kubectl`.
set -euo pipefail

BIN="${BIN:-$HOME/.local/bin}"
mkdir -p "$BIN"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

COSIGN=v2.6.5          # v2 on purpose: legacy .att/.sig tags, best supported by Kyverno + slsa-github-generator
SLSA_VERIFIER=v2.7.1
OPA=v1.21.4
TRIVY=0.76.1
GITLEAKS=8.30.1
CLOUDFLARED=2026.10.3
KYVERNO=v1.19.1
SEMGREP=1.178.0

TOOLS="${TOOLS:-cosign slsa-verifier opa trivy gitleaks kyverno cloudflared semgrep}"  # space-separated subset
want() { [[ " $TOOLS " == *" $1 "* ]]; }

gh_dl() { curl -fsSLO "https://github.com/$1/releases/download/$2/$3"; }
check() { # check <file> <checksums-file>
  grep -E "[[:space:]]\*?$1\$" "$2" | sha256sum -c - ; }

if want cosign; then
echo "== cosign";        gh_dl sigstore/cosign $COSIGN cosign-linux-amd64; gh_dl sigstore/cosign $COSIGN cosign_checksums.txt
check cosign-linux-amd64 cosign_checksums.txt; install -m755 cosign-linux-amd64 "$BIN/cosign"
fi

if want slsa-verifier; then
echo "== slsa-verifier"; gh_dl slsa-framework/slsa-verifier $SLSA_VERIFIER slsa-verifier-linux-amd64
curl -fsSL "https://raw.githubusercontent.com/slsa-framework/slsa-verifier/main/SHA256SUM.md" \
  | awk "/\[$SLSA_VERIFIER\]/{f=1;next} /^### /{f=0} f && /linux-amd64\$/" > slsa.sum
check slsa-verifier-linux-amd64 slsa.sum; install -m755 slsa-verifier-linux-amd64 "$BIN/slsa-verifier"
fi

if want opa; then
echo "== opa";           gh_dl open-policy-agent/opa $OPA opa_linux_amd64_static; gh_dl open-policy-agent/opa $OPA opa_linux_amd64_static.sha256
check opa_linux_amd64_static opa_linux_amd64_static.sha256; install -m755 opa_linux_amd64_static "$BIN/opa"
fi

if want trivy; then
echo "== trivy";         gh_dl aquasecurity/trivy v$TRIVY trivy_${TRIVY}_Linux-64bit.tar.gz; gh_dl aquasecurity/trivy v$TRIVY trivy_${TRIVY}_checksums.txt
check trivy_${TRIVY}_Linux-64bit.tar.gz trivy_${TRIVY}_checksums.txt; tar xzf trivy_${TRIVY}_Linux-64bit.tar.gz trivy && install -m755 trivy "$BIN/trivy"
fi

if want gitleaks; then
echo "== gitleaks";      gh_dl gitleaks/gitleaks v$GITLEAKS gitleaks_${GITLEAKS}_linux_x64.tar.gz; gh_dl gitleaks/gitleaks v$GITLEAKS gitleaks_${GITLEAKS}_checksums.txt
check gitleaks_${GITLEAKS}_linux_x64.tar.gz gitleaks_${GITLEAKS}_checksums.txt; tar xzf gitleaks_${GITLEAKS}_linux_x64.tar.gz gitleaks && install -m755 gitleaks "$BIN/gitleaks"
fi

if want kyverno; then
echo "== kyverno cli";   gh_dl kyverno/kyverno $KYVERNO kyverno-cli_${KYVERNO}_linux_x86_64.tar.gz; gh_dl kyverno/kyverno $KYVERNO checksums.txt
check kyverno-cli_${KYVERNO}_linux_x86_64.tar.gz checksums.txt; tar xzf kyverno-cli_${KYVERNO}_linux_x86_64.tar.gz kyverno && install -m755 kyverno "$BIN/kyverno"
fi

if want cloudflared; then
echo "== cloudflared";   gh_dl cloudflare/cloudflared $CLOUDFLARED cloudflared-linux-amd64
# cloudflared publishes checksums in the release notes body
curl -fsSL "https://api.github.com/repos/cloudflare/cloudflared/releases/tags/$CLOUDFLARED" \
  | python3 -c 'import sys,json,re; b=json.load(sys.stdin)["body"]; m=re.search(r"^cloudflared-linux-amd64: ([0-9a-f]{64})",b,re.M); print(m.group(1)+"  cloudflared-linux-amd64")' > cf.sum
check cloudflared-linux-amd64 cf.sum; install -m755 cloudflared-linux-amd64 "$BIN/cloudflared"
fi

if want semgrep; then
echo "== semgrep (venv)"
python3 -m venv "$HOME/.local/share/semgrep-venv"
"$HOME/.local/share/semgrep-venv/bin/pip" install -q "semgrep==$SEMGREP"
ln -sf "$HOME/.local/share/semgrep-venv/bin/semgrep" "$BIN/semgrep"
fi

echo "== done"
for t in $TOOLS; do printf '%-14s ' $t; command -v $t >/dev/null && echo ok || echo MISSING; done
