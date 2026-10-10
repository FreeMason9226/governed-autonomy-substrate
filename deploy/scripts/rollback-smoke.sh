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

if [[ -n "${REPLAY_ANCHOR_FILE:-}" ]]; then
  : "${GAS_URL:?GAS_URL is required when REPLAY_ANCHOR_FILE is set}"
  : "${GAS_TOKEN:?GAS_TOKEN is required when REPLAY_ANCHOR_FILE is set}"
  [[ -r "$REPLAY_ANCHOR_FILE" ]] || {
    echo "Replay anchor is not readable: $REPLAY_ANCHOR_FILE" >&2
    exit 2
  }
  auth_header="$(printf 'Authorization: %s %s' Bearer "$GAS_TOKEN")"
  curl --fail --silent --show-error \
    -H "$auth_header" \
    -H 'Content-Type: application/json' \
    --data-binary "@$REPLAY_ANCHOR_FILE" \
    "${GAS_URL%/}/audit/replay/certify" |
    python3 -c 'import json, sys; result = json.load(sys.stdin); sys.exit(0 if result.get("certified") is True else 1)'
fi
