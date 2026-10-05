"""Run cost-, environment-, approval-, and action-constrained infrastructure plans."""

from __future__ import annotations

import json
from typing import Any

from governed_autonomy import Policy

from demo._shared import DemoRuntime, build_runtime, identity_context


def build_demo() -> DemoRuntime:
    state: dict[str, Any] = {"planned_changes": []}

    def execute_plan(request: dict[str, Any]) -> dict[str, Any]:
        plan = {
            "action": request["action"],
            "provider": request["provider"],
            "environment": request["context"]["environment"],
            "resource": request["resource"],
            "estimated_cost": request.get("estimated_cost", 0),
            "status": "planned-in-local-sandbox",
        }
        state["planned_changes"].append(plan)
        return plan

    context = {"environment": "dev"}
    policies = (
        Policy(
            "CreateVirtualMachine-v1",
            ("CreateVirtualMachine",),
            {"CreateVirtualMachine": ("provider", "resource", "estimated_cost")},
            {},
            required_context=("environment", "identity_source", "subject", "tenant_id"),
            exact_context=context,
            max_numeric_fields={"CreateVirtualMachine": {"estimated_cost": 100}},
        ),
        Policy(
            "DeployCluster-v1",
            ("DeployCluster",),
            {"DeployCluster": ("provider", "resource", "estimated_cost")},
            {},
            required_context=("environment", "identity_source", "subject", "tenant_id"),
            exact_context=context,
            required_approvals={"DeployCluster": 1},
            max_numeric_fields={"DeployCluster": {"estimated_cost": 500}},
        ),
        Policy(
            "ModifyFirewallPolicy-v1",
            ("ModifyFirewallPolicy",),
            {"ModifyFirewallPolicy": ("provider", "resource", "change_ticket")},
            {},
            required_context=("environment", "identity_source", "subject", "tenant_id"),
            exact_context=context,
            required_approvals={"ModifyFirewallPolicy": 1},
        ),
        Policy(
            "DeleteResourceGroup-v1",
            (),
            {},
            {},
            required_context=("environment", "identity_source", "subject", "tenant_id"),
        ),
        Policy(
            "ScaleCluster-v1",
            ("ScaleCluster",),
            {"ScaleCluster": ("provider", "resource", "replicas")},
            {},
            required_context=("environment", "identity_source", "subject", "tenant_id"),
            exact_context=context,
            max_numeric_fields={"ScaleCluster": {"replicas": 20}},
        ),
    )
    return build_runtime(
        scenario="infrastructure-agent",
        policies=policies,
        actions=(
            "CreateVirtualMachine",
            "DeployCluster",
            "ModifyFirewallPolicy",
            "DeleteResourceGroup",
            "ScaleCluster",
        ),
        handler=execute_plan,
        state=state,
    )


def run_demo() -> tuple[DemoRuntime, dict[str, Any]]:
    runtime = build_demo()
    dev_actor = identity_context("agent:infra-operator")
    vm_request = {
        "action": "CreateVirtualMachine",
        "provider": "Terraform/Azure",
        "resource": "dev-vm-01",
        "estimated_cost": 68.00,
        "context": dev_actor,
    }
    vm = runtime.run(vm_request, "CreateVirtualMachine-v1")
    overspend = runtime.run(
        {**vm_request, "estimated_cost": 650},
        "CreateVirtualMachine-v1",
    )
    prod_firewall = runtime.run(
        {
            "action": "ModifyFirewallPolicy",
            "provider": "Kubernetes/AWS",
            "resource": "prod-edge",
            "change_ticket": "CHG-1234",
            "context": {**dev_actor, "environment": "prod"},
        },
        "ModifyFirewallPolicy-v1",
    )
    delete_denied = runtime.run(
        {
            "action": "DeleteResourceGroup",
            "provider": "Azure",
            "resource": "prod-rg",
            "context": dev_actor,
        },
        "DeleteResourceGroup-v1",
    )
    cluster_request = {
        "action": "DeployCluster",
        "provider": "Kubernetes",
        "resource": "dev-cluster-01",
        "estimated_cost": 240,
        "context": dev_actor,
    }
    cluster_denied = runtime.run(cluster_request, "DeployCluster-v1")
    approval = runtime.approve(cluster_request, "DeployCluster-v1")
    cluster_approved = runtime.run(
        cluster_request,
        "DeployCluster-v1",
        approval=approval,
    )
    return runtime, {
        "runs": [vm, overspend, prod_firewall, delete_denied, cluster_denied, cluster_approved],
        "sandbox_state": runtime.state,
        "audit": runtime.audit_report(),
    }


def main() -> int:
    _runtime, result = run_demo()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
