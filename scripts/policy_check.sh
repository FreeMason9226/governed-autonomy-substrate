#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat >&2 <<EOF
Usage: $0 run --pr ID --base-ref REF --head-ref REF --out FILE --threshold N

Evaluate changed paths between the base and head Git refs with OPA. The check
fails when the resulting risk score is greater than or equal to the threshold.
Required tools: git, opa, jq.
EOF
}

error() {
  echo "policy_check: $*" >&2
}

command="${1:-}"
case "$command" in
  run) shift ;;
  -h|--help|help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

pr=""
base_ref=""
head_ref=""
out=""
threshold=""
while (($#)); do
  case "$1" in
    --pr|--base-ref|--head-ref|--out|--threshold)
      if (($# < 2)) || [[ -z "$2" || "$2" == --* ]]; then
        error "missing value for $1"
        usage
        exit 2
      fi
      option="$1"
      value="$2"
      case "$option" in
        --pr) pr="$value" ;;
        --base-ref) base_ref="$value" ;;
        --head-ref) head_ref="$value" ;;
        --out) out="$value" ;;
        --threshold) threshold="$value" ;;
      esac
      shift 2
      ;;
    *)
      error "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

for required in pr base_ref head_ref out threshold; do
  if [[ -z "${!required}" ]]; then
    error "missing required option: --${required//_/-}"
    usage
    exit 2
  fi
done

if [[ ! "$pr" =~ ^[0-9]+$ ]]; then
  error "--pr must be a non-negative integer"
  exit 2
fi
if [[ ! "$threshold" =~ ^[0-9]+$ ]]; then
  error "--threshold must be a non-negative integer"
  exit 2
fi

for tool in git opa jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    error "required dependency '$tool' was not found in PATH"
    exit 2
  fi
done

if [[ ! -d policy/regos ]]; then
  error "policy directory policy/regos is missing"
  exit 2
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
changed_paths_file="$tmp_dir/changed-paths"
if ! git diff --name-only -z "$base_ref" "$head_ref" >"$changed_paths_file"; then
  error "could not diff refs '$base_ref' and '$head_ref'; ensure both refs are available locally"
  exit 2
fi

changed_files=()
while IFS= read -r -d '' path; do
  changed_files+=("$path")
done <"$changed_paths_file"

jq -n --argjson pr_id "$pr" --args \
  '{pr_id: $pr_id, changed_files: $ARGS.positional}' \
  "${changed_files[@]}" >"$tmp_dir/input.json"

if ! opa eval --data policy/regos --input "$tmp_dir/input.json" \
  --format json 'data.policy.result' >"$tmp_dir/evaluation.json"; then
  error "OPA evaluation failed"
  exit 2
fi

if ! jq -e '
  .result | length == 1 and
  (. [0].expressions | length == 1) and
  (. [0].expressions[0].value | (.risk_score | type == "number") and
    (.rules_triggered | type == "array") and (.rationale | type == "string"))
' "$tmp_dir/evaluation.json" >/dev/null; then
  error "OPA returned an unexpected result"
  exit 2
fi

policy_result="$(jq -c '.result[0].expressions[0].value' "$tmp_dir/evaluation.json")"
risk_score="$(jq -r '.risk_score' <<<"$policy_result")"
timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

out_dir="$(dirname -- "$out")"
mkdir -p "$out_dir"
jq -n \
  --argjson pr_id "$pr" \
  --argjson risk_score "$risk_score" \
  --argjson rules_triggered "$(jq -c '.rules_triggered' <<<"$policy_result")" \
  --arg rationale "$(jq -r '.rationale' <<<"$policy_result")" \
  --arg timestamp "$timestamp" \
  '{pr_id: $pr_id, risk_score: $risk_score, rules_triggered: $rules_triggered, rationale: $rationale, timestamp: $timestamp}' \
  >"$out"

echo "Policy risk score: $risk_score (threshold: $threshold)"
if ((risk_score >= threshold)); then
  error "risk score meets or exceeds the threshold"
  exit 1
fi
