"""Run the full governed-autonomy PR lifecycle locally, offline, and deterministically.

AI opens PR -> policy flags -> human approval (MODELED, clearly marked) -> signed GAA
-> GAA verified -> merge-ready event -> hash-chained audit JSON.
Nothing is merged and no real approval is claimed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo import attest, bot, pr_policy  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "ai_change.json")
SIM_APPROVER = "simulated-human-reviewer"
CLOCK = [f"2026-01-01T00:00:0{i}Z" for i in range(6)]


def run(out_dir: str, approve: bool = True) -> dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)
    with open(FIXTURE, encoding="utf-8") as handle:
        fixture = json.load(handle)
    audit = attest.AuditLog()
    pr = bot.dry_run_pr()
    audit.append("pr_opened", CLOCK[0], {"pr_number": pr["number"], "author": pr["user"]["login"], "simulated": True})

    policy = pr_policy.evaluate(fixture["pull_request"], fixture["files"])
    with open(os.path.join(out_dir, "policy-result.json"), "w", encoding="utf-8") as handle:
        json.dump(policy, handle, indent=2, sort_keys=True)
        handle.write("\n")
    audit.append("policy_evaluated", CLOCK[1], {"status": policy["status"], "reasons": policy["reasons"]})

    summary: dict[str, Any] = {"policy_status": policy["status"], "merge_ready": False}
    if policy["requires_human_approval"] and not approve:
        summary["note"] = "awaiting human approval; no GAA issued"
    else:
        if policy["requires_human_approval"]:
            audit.append("human_approved", CLOCK[2], {
                "approver": SIM_APPROVER, "simulated": True,
                "note": "modeled approval; in live mode this is read from GitHub reviews"})
        key = attest.load_private_key(simulated=True)
        claims = attest.build_claims(policy, SIM_APPROVER, True, CLOCK[3])
        gaa = attest.sign_gaa(claims, key)
        with open(os.path.join(out_dir, "gaa.json"), "w", encoding="utf-8") as handle:
            json.dump(gaa, handle, indent=2, sort_keys=True)
            handle.write("\n")
        audit.append("gaa_signed", CLOCK[3], {"public_key": gaa["public_key"]})
        verified = attest.verify_gaa(gaa, attest.public_key_b64(key))
        audit.append("gaa_verified", CLOCK[4], {"valid": verified})
        if verified:
            audit.append("merge_ready", CLOCK[5], {"pr_number": pr["number"], "note": "a human must still merge"})
            summary["merge_ready"] = True
        summary["gaa_valid"] = verified

    with open(os.path.join(out_dir, "audit.json"), "w", encoding="utf-8") as handle:
        json.dump({"records": audit.records}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    summary["audit_chain_valid"] = attest.AuditLog.verify(audit.records)
    summary["audit_events"] = [r["event"] for r in audit.records]
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="demo-out", help="output directory (default: demo-out)")
    parser.add_argument("--no-approval", action="store_true", help="stop after the policy flag")
    args = parser.parse_args(argv)
    summary = run(args.out, approve=not args.no_approval)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
