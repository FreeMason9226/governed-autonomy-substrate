"""Create and sign a pull-request attestation."""

from __future__ import annotations

import argparse
import json
import math
import sys
from datetime import UTC, datetime
from pathlib import Path

from attest.common import load_private_key, sign_attestation


def build_attestation(
    pr_id: int,
    actor: str,
    approver: str,
    policy_id: str,
    risk_score: float,
    rationale: str,
    commit_sha: str,
    private_key: object,
    timestamp: str | None = None,
) -> dict[str, object]:
    payload = {
        "pr_id": pr_id,
        "actor": actor,
        "approver": approver,
        "policy_id": policy_id,
        "risk_score": risk_score,
        "rationale": rationale,
        "timestamp": timestamp or datetime.now(UTC).replace(microsecond=0).isoformat(),
        "commit_sha": commit_sha,
    }
    return sign_attestation(payload, private_key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, type=int, dest="pr_id")
    parser.add_argument("--actor", required=True)
    parser.add_argument("--approver", required=True)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--risk-score", required=True, type=float)
    parser.add_argument("--rationale", required=True)
    parser.add_argument("--commit", required=True, dest="commit_sha")
    parser.add_argument("--key", required=True, help="PEM-encoded RSA or ECDSA private key")
    parser.add_argument("--out", required=True, help="output JSON file")
    args = parser.parse_args(argv)

    if not math.isfinite(args.risk_score):
        parser.error("--risk-score must be finite")
    try:
        key = load_private_key(args.key)
        attestation = build_attestation(
            args.pr_id,
            args.actor,
            args.approver,
            args.policy_id,
            args.risk_score,
            args.rationale,
            args.commit_sha,
            key,
        )
        output = Path(args.out)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as output_file:
            json.dump(attestation, output_file, indent=2, sort_keys=True, allow_nan=False)
            output_file.write("\n")
    except (OSError, TypeError, ValueError) as exc:
        print(f"attestation generation failed: {exc}", file=sys.stderr)
        return 1
    print(f"Attestation written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
