#!/usr/bin/env bash
# Admission demo: signed+attested digest is admitted; a locally built unsigned image is rejected.
# usage: deploy/demo.sh good sha256:<digest> | deploy/demo.sh unsigned
set -uo pipefail
cd "$(dirname "$0")"
kubectl config use-context kind-slsa-lab >/dev/null
case "${1:?good|unsigned}" in
  good)
    REF="ghcr.io/rajumandala/slsa-pipeline-lab@${2:?digest}"; NAME=hello ;;
  unsigned)
    docker build -q -t localhost:5001/lab-app:unsigned .. >/dev/null
    docker push -q localhost:5001/lab-app:unsigned >/dev/null
    REF="slsa-lab-registry:5000/lab-app:unsigned"; NAME=hello-unsigned ;;
esac
kubectl -n demo delete pod "$NAME" --ignore-not-found --wait >/dev/null
sed -e "s#IMAGE_REF#$REF#" -e "s#name: hello\$#name: $NAME#" app.yaml | kubectl apply -f -
rc=$?
[ "$1" = good ] && [ $rc -eq 0 ] && kubectl -n demo wait --for=condition=Ready pod/$NAME --timeout=120s
exit $rc
