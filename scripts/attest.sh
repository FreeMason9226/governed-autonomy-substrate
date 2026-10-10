#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
AUDIT_LEDGER="${AUDIT_LEDGER:-audit/ledger.jsonl}"

usage() {
  echo "Usage: $0 generate --pr N --actor NAME --approver NAME --commit SHA --key PRIVATE_KEY --policy-id ID --risk-score N --rationale TEXT [--out FILE] [--pubkey FILE]" >&2
  echo "       $0 verify --attest FILE [--pubkey FILE]" >&2
}

command="${1:-}"
if [[ -z "$command" ]]; then
  usage
  exit 2
fi
shift

case "$command" in
  generate)
    pr=""
    actor=""
    approver=""
    commit=""
    key="attest/demo_key.pem"
    pubkey=""
    out="attest/output.json"
    policy_id=""
    risk_score=""
    rationale=""
    while (($#)); do
      case "$1" in
        --pr|--actor|--approver|--commit|--key|--out|--pubkey|--policy-id|--risk-score|--rationale)
          if (($# < 2)); then
            echo "Missing value for $1" >&2
            exit 2
          fi
          option="$1"
          value="$2"
          case "$option" in
            --pr) pr="$value" ;;
            --actor) actor="$value" ;;
            --approver) approver="$value" ;;
            --commit) commit="$value" ;;
            --key) key="$value" ;;
            --out) out="$value" ;;
            --pubkey) pubkey="$value" ;;
            --policy-id) policy_id="$value" ;;
            --risk-score) risk_score="$value" ;;
            --rationale) rationale="$value" ;;
          esac
          shift 2
          ;;
        *)
          echo "Unknown argument: $1" >&2
          usage
          exit 2
          ;;
      esac
    done
    for required in pr actor approver commit policy_id risk_score rationale; do
      if [[ -z "${!required}" ]]; then
        echo "Missing required option for $required" >&2
        usage
        exit 2
      fi
    done
    if [[ -z "$pubkey" ]]; then
      if [[ "$key" == *.pem ]]; then
        pubkey="${key%.pem}.pub"
      else
        pubkey="${key}.pub"
      fi
    fi
    python3 -m attest.generate_attestation \
      --pr "$pr" --actor "$actor" --approver "$approver" \
      --commit "$commit" --key "$key" --out "$out" \
      --policy-id "$policy_id" --risk-score "$risk_score" --rationale "$rationale"
    python3 -m attest.verify_attestation --attest "$out" --pubkey "$pubkey"
    python3 -c 'from attest.common import append_to_ledger; import sys; append_to_ledger(sys.argv[1], sys.argv[2])' \
      "$out" "$AUDIT_LEDGER"
    echo "Attestation saved to $out and appended to $AUDIT_LEDGER"
    ;;
  verify)
    attest=""
    pubkey="attest/demo_key.pub"
    while (($#)); do
      case "$1" in
        --attest|--pubkey)
          if (($# < 2)); then
            echo "Missing value for $1" >&2
            exit 2
          fi
          if [[ "$1" == "--attest" ]]; then
            attest="$2"
          else
            pubkey="$2"
          fi
          shift 2
          ;;
        *)
          echo "Unknown argument: $1" >&2
          usage
          exit 2
          ;;
      esac
    done
    if [[ -z "$attest" ]]; then
      echo "Missing required option: --attest" >&2
      usage
      exit 2
    fi
    python3 -m attest.verify_attestation --attest "$attest" --pubkey "$pubkey"
    ;;
  *)
    usage
    exit 2
    ;;
esac
