"""Run the safe $100k wire-transfer approval workflow."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from governed_autonomy import Policy

from demo._shared import DemoRuntime, build_runtime, identity_context

APPROVER = "finance:treasury-reviewer"
REQUESTOR = "agent:accounts-payable"


def build_demo() -> DemoRuntime:
    state: dict[str, Any] = {"transfers": []}

    def execute_transfer(request: dict[str, Any]) -> dict[str, Any]:
        transfer = {
            "transfer_id": f"wire-{len(state['transfers']) + 1:04d}",
            "amount": request["amount"],
            "currency": request["currency"],
            "beneficiary": request["beneficiary"],
            "status": "submitted-to-local-sandbox-ledger",
        }
        state["transfers"].append(transfer)
        return transfer

    policies = (
        Policy(
            "TransferUnder10000-v1",
            ("WireTransfer",),
            {"WireTransfer": ("amount", "currency", "beneficiary")},
            {},
            required_context=("identity_source", "subject", "tenant_id"),
            max_numeric_fields={"WireTransfer": {"amount": 9999.99}},
        ),
        Policy(
            "TransferRequiresApproval-v1",
            ("WireTransfer",),
            {"WireTransfer": ("amount", "currency", "beneficiary")},
            {},
            required_context=("identity_source", "subject", "tenant_id"),
            required_approvals={"WireTransfer": 1},
            max_numeric_fields={"WireTransfer": {"amount": 500000.00}},
        ),
        Policy(
            "HighRiskTransferDenied-v1",
            (),
            {},
            {},
            required_context=("identity_source", "subject", "tenant_id"),
        ),
    )
    return build_runtime(
        scenario="financial-approval",
        policies=policies,
        actions=("WireTransfer",),
        handler=execute_transfer,
        state=state,
    )


def run_demo() -> tuple[DemoRuntime, dict[str, Any]]:
    runtime = build_demo()
    request = {
        "action": "WireTransfer",
        "amount": 100000.00,
        "currency": "USD",
        "beneficiary": "Example Beneficiary",
        "context": identity_context(REQUESTOR),
    }
    denied = runtime.run(request, "TransferRequiresApproval-v1")
    approval = runtime.approve(request, "TransferRequiresApproval-v1")
    completed = runtime.run(
        request,
        "TransferRequiresApproval-v1",
        approval=approval,
    )
    unsafe = runtime.run(
        {
            **request,
            "amount": 750000,
            "context": identity_context(REQUESTOR),
        },
        "HighRiskTransferDenied-v1",
    )
    return runtime, {
        "requestor": REQUESTOR,
        "approver": APPROVER,
        "approval_required_without_signature": denied["status"] == "blocked",
        "approved_transfer": completed,
        "high_risk_transfer": unsafe,
        "sandbox_transfers": runtime.state["transfers"],
        "audit": runtime.audit_report(),
    }


def main() -> int:
    _runtime, result = run_demo()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
