"""
GAS Ecosystem Demo: Google Agent-to-Agent (A2A) Governed Task Delegation.

Demonstrates:
- Coordinator Agent requesting a GAA and delegating a task to Worker Agent.
- Signing an A2ATaskDelegation artifact targeted at Worker Agent.
- Worker Agent's A2AGuard verifying delegator signature, recipient targeting, and GAA.
- Executing the delegated task with single-use nonce claim and audit trail.
"""

from governed_autonomy import (
    A2AGuard,
    A2ATaskDelegation,
    AuthorizationIssuer,
    ExecutionBoundary,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
)


def main() -> None:
    print("=== GAS Agent-to-Agent (A2A) Delegation Demo ===")

    # 1. Provision Agent Identities and Shared Trust Store
    gov_key = KeyPair.generate("platform-governor")
    coordinator_key = KeyPair.generate("agent-coordinator-alpha")
    worker_key = KeyPair.generate("agent-worker-beta")

    trust = TrustStore()
    trust.add(gov_key.key_id, gov_key.public_key)
    trust.add(coordinator_key.key_id, coordinator_key.public_key)
    trust.add(worker_key.key_id, worker_key.public_key)

    # 2. Worker node execution barrier and policy
    policy = Policy(
        policy_id="worker-delegation-policy",
        allowed_actions=("process_dataset",),
        required_fields={"process_dataset": ("dataset_id", "row_count")},
        exact_fields={},
        max_request_bytes=64 * 1024,
        max_ttl_seconds=300,
    )
    registry = PolicyRegistry((policy,))
    worker_replay = ReplayLog()
    issuer = AuthorizationIssuer(issuer=gov_key, replay_log=worker_replay)
    boundary = ExecutionBoundary(
        replay_log=worker_replay,
        trust_store=trust,
        policy_registry=registry,
    )

    worker_guard = A2AGuard(
        recipient_id=worker_key.key_id,
        trust_store=trust,
        boundary=boundary,
    )

    # 3. Coordinator prepares and authorizes task
    print(f"Coordinator ({coordinator_key.key_id}) preparing task for Worker ({worker_key.key_id})...")
    task_args = {"dataset_id": "ds-analytics-2026", "row_count": 50000}
    action_req = {"action": "process_dataset", **task_args, "context": {}}

    gaa = issuer.authorize(action_req, policy)
    print(f"GAA Issued: nonce={gaa.nonce}")

    # 4. Coordinator signs A2ATaskDelegation envelope
    delegation = A2ATaskDelegation.create(
        delegator=coordinator_key,
        recipient_id=worker_key.key_id,
        task_id="task-batch-001",
        action="process_dataset",
        payload=task_args,
        gaa=gaa,
    )
    print("A2ATaskDelegation envelope signed by coordinator.")

    # 5. Worker receives delegation envelope and executes
    def worker_processing_logic(req: dict) -> dict:
        return {
            "status": "completed",
            "dataset_id": req["dataset_id"],
            "processed_rows": req["row_count"],
        }

    print("Worker verifying and executing delegation through A2AGuard...")
    worker_result = worker_guard.receive_and_execute(delegation, worker_processing_logic)

    print("\n--- Delegation Succeeded ---")
    print(f"Worker Result:   {worker_result}")
    print(f"Delegator ID:    {delegation.delegator_id}")
    print(f"Recipient ID:    {delegation.recipient_id}")
    print(f"Delegation Sig:  {delegation.signature[:24]}...")

    # 6. Verify replay log integrity
    summary = worker_replay.audit_summary()
    print(f"\nWorker Replay Frames: {summary['frame_count']} (Chain Verified: {worker_replay.verify_chain()})")


if __name__ == "__main__":
    main()
