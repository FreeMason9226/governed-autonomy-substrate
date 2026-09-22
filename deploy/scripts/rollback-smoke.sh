#!/usr/bin/env bash
set -euo pipefail

: "${NAMESPACE:=governed-autonomy}"
: "${RELEASE:=governed-autonomy}"
: "${REVISION:=}"

if [[ -z "$REVISION" ]]; then
  echo 'REVISION is required; choose a known-good Helm revision.' >&2
  exit 2
fi
helm history "$RELEASE" --namespace "$NAMESPACE"
helm rollback "$RELEASE" "$REVISION" --namespace "$NAMESPACE" --wait --timeout 5m
kubectl rollout status deployment/"$RELEASE" --namespace "$NAMESPACE" --timeout=5m
kubectl get pods --namespace "$NAMESPACE" -l app.kubernetes.io/name=governed-autonomy
