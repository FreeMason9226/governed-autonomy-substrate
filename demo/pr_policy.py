"""Deterministic demo policy check for pull requests (no network, no execution of PR code)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any

SCHEMA_VERSION = "gaa-demo-policy-result/v1"
PROTECTED_PREFIXES = ("src/", ".github/", "deploy/", "schemas/")
AI_LABEL = "ai-authored"
AI_LOGIN_SUFFIXES = ("-bot", "[bot]")
MAX_CHANGED_LINES = 200


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def evaluate(pr: dict[str, Any], files: list[dict[str, Any]]) -> dict[str, Any]:
    """Return a policy result. Same input always yields the same output."""
    reasons: list[str] = []
    login = str((pr.get("user") or {}).get("login", ""))
    labels = {str(label.get("name", "")) for label in pr.get("labels") or []}
    ai_authored = AI_LABEL in labels or login.endswith(AI_LOGIN_SUFFIXES)
    if ai_authored:
        protected = sorted(
            {f["filename"] for f in files if str(f.get("filename", "")).startswith(PROTECTED_PREFIXES)}
        )
        for name in protected:
            reasons.append(f"ai-authored change touches protected path: {name}")
        changed = sum(int(f.get("additions", 0)) + int(f.get("deletions", 0)) for f in files)
        if changed > MAX_CHANGED_LINES:
            reasons.append(f"ai-authored change exceeds {MAX_CHANGED_LINES} changed lines ({changed})")
    flagged = bool(reasons)
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "flag_requires_human_approval" if flagged else "pass",
        "requires_human_approval": flagged,
        "pr_number": int(pr.get("number", 0)),
        "head_sha": str((pr.get("head") or {}).get("sha", "")),
        "reasons": reasons,
        "input_digest": hashlib.sha256(canonical({"pr": pr, "files": files})).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event", required=True, help="JSON file with a pull_request object (GitHub event or fixture)")
    parser.add_argument("--files", help="JSON array of PR files (default: 'files' key in --event)")
    parser.add_argument("--output", help="write result JSON here (default: stdout)")
    args = parser.parse_args(argv)
    with open(args.event, encoding="utf-8") as handle:
        event = json.load(handle)
    if args.files:
        with open(args.files, encoding="utf-8") as handle:
            files = json.load(handle)
    else:
        files = event.get("files", [])
    result = evaluate(event["pull_request"], files)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    # Exit 0 for both outcomes: a flag is a policy result, not a tool failure.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
