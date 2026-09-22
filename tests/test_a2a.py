from __future__ import annotations

import pytest

from governed_autonomy import (
    AuthorizationError,
    AuthorizationIssuer,
    ExecutionBoundary,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
)
from governed_autonomy.a2a import A2AGuard, A2ATaskDelegation
from governed_autonomy.policy import DeterministicArbiter


@pytest.fixture
def a2a_setup() -> tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy]:
    # 1. Keys
    gov_issuer_key = KeyPair.generate("central-governor")
    delegator_key = KeyPair.generate("agent-coordinator")
    worker_key = KeyPair.generate("agent-worker")

    # 2. Shared Trust Store
    trust = TrustStore()
    trust.add(gov_issuer_key.key_id, gov_issuer_key.public_key)
    trust.add(delegator_key.key_id, delegator_key.public_key)
    trust.add(worker_key.key_id, worker_key.public_key)

    # 3. Policy & Boundary
    policy = Policy(
        policy_id="worker-tasks-v1",
        allowed_actions=("process_batch",),
        required_fields={"process_batch": ("batch_id", "items")},
        exact_fields={},
        max_request_bytes=64 * 1024,
        max_ttl_seconds=300,
    )
    registry = PolicyRegistry((policy,))
    replay = ReplayLog()
    arbiter = DeterministicArbiter(trust_store=trust)

    issuer = AuthorizationIssuer(issuer=gov_issuer_key, replay_log=replay, arbiter=arbiter)
    boundary = ExecutionBoundary(
        replay_log=replay,
        trust_store=trust,
        policy_registry=registry,
        arbiter=arbiter,
    )

    return (
        gov_issuer_key,
        delegator_key,
        worker_key,
        trust,
        replay,
        issuer,
        boundary,
        policy,
    )


def test_successful_a2a_delegation_flow(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, delegator_key, worker_key, trust, replay, issuer, boundary, policy = a2a_setup

    guard = A2AGuard(
        recipient_id=worker_key.key_id,
        trust_store=trust,
        boundary=boundary,
    )

    # 1. Delegator requests GAA for the task
    task_payload = {"batch_id": "batch-101", "items": [1, 2, 3]}
    action_req = {"action": "process_batch", **task_payload, "context": {}}
    gaa = issuer.authorize(action_req, policy)

    # 2. Delegator packages and signs the delegation envelope
    delegation = A2ATaskDelegation.create(
        delegator=delegator_key,
        recipient_id=worker_key.key_id,
        task_id="task-999",
        action="process_batch",
        payload=task_payload,
        gaa=gaa,
    )

    # 3. Worker executes task through guard
    def worker_handler(req: dict) -> str:
        return f"processed {len(req['items'])} items for {req['batch_id']}"

    result = guard.receive_and_execute(delegation, worker_handler)
    assert result == "processed 3 items for batch-101"

    # Replay log verification
    assert replay.verify_chain() is True
    summary = replay.audit_summary()
    assert summary["execution_count"] == 1
    assert summary["success_count"] == 1


def test_recipient_mismatch_rejected(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, delegator_key, _, trust, _, issuer, boundary, policy = a2a_setup

    guard = A2AGuard(
        recipient_id="agent-worker-actual",
        trust_store=trust,
        boundary=boundary,
    )

    task_payload = {"batch_id": "batch-102", "items": [4, 5]}
    gaa = issuer.authorize({"action": "process_batch", **task_payload, "context": {}}, policy)

    # Targeted to agent-worker-different
    delegation = A2ATaskDelegation.create(
        delegator=delegator_key,
        recipient_id="agent-worker-different",
        task_id="task-102",
        action="process_batch",
        payload=task_payload,
        gaa=gaa,
    )

    with pytest.raises(AuthorizationError, match="delegation recipient mismatch"):
        guard.receive_and_execute(delegation, lambda req: "ok")


def test_unknown_delegator_rejected(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, _, worker_key, trust, _, issuer, boundary, policy = a2a_setup

    untrusted_delegator = KeyPair.generate("untrusted-agent")

    guard = A2AGuard(
        recipient_id=worker_key.key_id,
        trust_store=trust,
        boundary=boundary,
    )

    task_payload = {"batch_id": "batch-103", "items": [1]}
    gaa = issuer.authorize({"action": "process_batch", **task_payload, "context": {}}, policy)

    delegation = A2ATaskDelegation.create(
        delegator=untrusted_delegator,
        recipient_id=worker_key.key_id,
        task_id="task-103",
        action="process_batch",
        payload=task_payload,
        gaa=gaa,
    )

    with pytest.raises(AuthorizationError, match="unknown or revoked delegator key"):
        guard.receive_and_execute(delegation, lambda req: "ok")


def test_tampered_payload_rejected(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, delegator_key, worker_key, trust, _, issuer, boundary, policy = a2a_setup

    guard = A2AGuard(
        recipient_id=worker_key.key_id,
        trust_store=trust,
        boundary=boundary,
    )

    task_payload = {"batch_id": "batch-104", "items": [1]}
    gaa = issuer.authorize({"action": "process_batch", **task_payload, "context": {}}, policy)

    delegation = A2ATaskDelegation.create(
        delegator=delegator_key,
        recipient_id=worker_key.key_id,
        task_id="task-104",
        action="process_batch",
        payload=task_payload,
        gaa=gaa,
    )

    # Tamper payload
    tampered = A2ATaskDelegation(
        delegator_id=delegation.delegator_id,
        recipient_id=delegation.recipient_id,
        task_id=delegation.task_id,
        action=delegation.action,
        payload={"batch_id": "batch-tampered", "items": [999]},
        gaa=delegation.gaa,
        signature=delegation.signature,
    )

    with pytest.raises(AuthorizationError, match="invalid delegator signature"):
        guard.receive_and_execute(tampered, lambda req: "ok")


def test_action_mismatch_rejected(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, delegator_key, worker_key, trust, _, issuer, boundary, policy = a2a_setup

    guard = A2AGuard(
        recipient_id=worker_key.key_id,
        trust_store=trust,
        boundary=boundary,
    )

    task_payload = {"batch_id": "batch-105", "items": [1]}
    gaa = issuer.authorize({"action": "process_batch", **task_payload, "context": {}}, policy)

    # Delegation action claims "other_action" while GAA is for "process_batch"
    delegation = A2ATaskDelegation.create(
        delegator=delegator_key,
        recipient_id=worker_key.key_id,
        task_id="task-105",
        action="other_action",
        payload=task_payload,
        gaa=gaa,
    )

    with pytest.raises(AuthorizationError, match="action mismatch"):
        guard.receive_and_execute(delegation, lambda req: "ok")


def test_replay_duplicate_nonce_rejected(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, delegator_key, worker_key, trust, _, issuer, boundary, policy = a2a_setup

    guard = A2AGuard(
        recipient_id=worker_key.key_id,
        trust_store=trust,
        boundary=boundary,
    )

    task_payload = {"batch_id": "batch-106", "items": [1]}
    gaa = issuer.authorize({"action": "process_batch", **task_payload, "context": {}}, policy)

    delegation = A2ATaskDelegation.create(
        delegator=delegator_key,
        recipient_id=worker_key.key_id,
        task_id="task-106",
        action="process_batch",
        payload=task_payload,
        gaa=gaa,
    )

    # First execution succeeds
    guard.receive_and_execute(delegation, lambda req: "ok")

    # Second execution with same nonce MUST fail
    with pytest.raises(AuthorizationError):
        guard.receive_and_execute(delegation, lambda req: "ok")


def test_delegation_dict_roundtrip(
    a2a_setup: tuple[KeyPair, KeyPair, KeyPair, TrustStore, ReplayLog, AuthorizationIssuer, ExecutionBoundary, Policy],
) -> None:
    _, delegator_key, worker_key, _, _, issuer, _, policy = a2a_setup

    task_payload = {"batch_id": "batch-107", "items": [1]}
    gaa = issuer.authorize({"action": "process_batch", **task_payload, "context": {}}, policy)

    d1 = A2ATaskDelegation.create(
        delegator=delegator_key,
        recipient_id=worker_key.key_id,
        task_id="task-107",
        action="process_batch",
        payload=task_payload,
        gaa=gaa,
    )

    as_dict = d1.to_dict()
    d2 = A2ATaskDelegation.from_dict(as_dict)
    assert d2 == d1
