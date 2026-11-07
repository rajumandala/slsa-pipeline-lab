#!/usr/bin/env bash
# kind cluster + Kyverno + a local (unsigned) registry for the negative demo.
set -euo pipefail
KYVERNO=v1.19.1
REG=slsa-lab-registry
cd "$(dirname "$0")"

kind get clusters | grep -qx slsa-lab || kind create cluster --config kind.yaml
kubectl config use-context kind-slsa-lab

# Plain local registry on the kind docker network (reachable in-cluster as $REG:5000)
docker inspect "$REG" >/dev/null 2>&1 || docker run -d --restart=always --name "$REG" -p 127.0.0.1:5001:5000 registry:2
docker network connect kind "$REG" 2>/dev/null || true

# Allow plain-HTTP for the local registry only so the unsigned image is rejected for
# "no signature" rather than a TLS error. (Lab only: never do this in a real cluster.)
curl -fsSL "https://github.com/kyverno/kyverno/releases/download/$KYVERNO/install.yaml" \
  | sed 's/--allowInsecureRegistry=false/--allowInsecureRegistry=true/' \
  | kubectl apply --server-side --force-conflicts -f - >/dev/null
kubectl -n kyverno rollout status deploy/kyverno-admission-controller --timeout=300s

# the admission webhook can lag the rollout by a few seconds
for i in $(seq 1 20); do kubectl apply -f kyverno-policy.yaml && break; sleep 6; done
kubectl wait --for=condition=Ready clusterpolicy/require-slsa-and-scans --timeout=120s
kubectl get ns demo >/dev/null 2>&1 || kubectl create ns demo
