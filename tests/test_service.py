import pytest

from governed_autonomy import (
    AuthorizationError,
    AuthorizationIssuer,
    ExecutionBoundary,
    GovernedService,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
)


def build_service():
    issuer = KeyPair.generate()
    log = ReplayLog()
    service = GovernedService(
        issuer=AuthorizationIssuer(
            issuer=issuer,
            replay_log=log,
            nonce_factory=lambda: "service-nonce",
        ),
        boundary=ExecutionBoundary(
            replay_log=log,
            issuer_keys={issuer.key_id: issuer.public_key},
            clock=lambda: 100,
        ),
        policies={
            "files-v1": Policy(
                "files-v1",
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            )
        },
        actions={"write_file": lambda request: request["content"]},
    )
    return service


def test_service_authorizes_and_executes_named_action():
    service = build_service()
    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        "files-v1",
    )

    assert service.execute_json(artifact.to_json()) == "ok"


def test_service_accepts_immutable_policy_registry():
    service = build_service()
    registry = PolicyRegistry(service.policies.policies())
    service = GovernedService(
        issuer=service.issuer,
        boundary=service.boundary,
        policies=registry,
        actions=service.actions,
    )

    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "registry"},
        "files-v1",
    )
    assert service.execute(artifact) == "registry"


def test_service_rejects_unknown_policy_and_action():
    service = build_service()
    with pytest.raises(AuthorizationError, match="unknown policy"):
        service.authorize({"action": "write_file"}, "missing")
    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        "files-v1",
    )
    tampered_request = artifact.__class__(
        **{
            **artifact.to_dict(),
            "action_request": {"action": "not-registered"},
        }
    )
    with pytest.raises(AuthorizationError, match="unknown executable action"):
        service.execute(tampered_request)


def test_service_governance_log_records_durable_policy_and_trust_lifecycle_events():
    from governed_autonomy import build_demo_service
    from governed_autonomy.canonical import b64encode

    service, issuer, _ = build_demo_service()
    reviewer = KeyPair.generate("reviewer")
    reviewer2 = KeyPair.generate("reviewer2")
    service.boundary.trust_store.add(reviewer.key_id, reviewer.public_key)
    service.boundary.trust_store.add(reviewer2.key_id, reviewer2.public_key)

    assert service.governance_log() == ()

    new_policy = Policy(
        "demo-files-v2",
        ("write_file",),
        {"write_file": ("path", "content")},
        {"write_file": {"path": "renamed.txt"}},
    )
    proposal = service.policy_change_manager.propose(
        new_policy=new_policy, proposer=issuer, rationale="rename default output"
    )
    service.policy_change_manager.approve(proposal.proposal_id, approver=reviewer)
    service.policy_change_manager.approve(proposal.proposal_id, approver=reviewer2)
    service.policy_change_manager.activate(proposal.proposal_id)

    new_key = KeyPair.generate("new-key")
    new_public_key_b64 = b64encode(new_key.public_key_bytes())
    prepared = service.trust_change_manager.prepare_add(
        key_id=new_key.key_id,
        public_key_b64=new_public_key_b64,
        requested_by_key_id=issuer.key_id,
    )
    signature = issuer.sign(prepared["unsigned_payload"].encode("utf-8"))
    service.trust_change_manager.submit_add(
        key_id=new_key.key_id,
        public_key_b64=new_public_key_b64,
        requested_by_key_id=issuer.key_id,
        signature=signature,
    )

    events = service.governance_log()
    assert [event["event"] for event in events] == [
        "policy.proposed",
        "policy.approved",
        "policy.approved",
        "policy.activated",
        "trust.key_added",
    ]
    assert [event["subject_id"] for event in events] == [
        proposal.proposal_id,
        proposal.proposal_id,
        proposal.proposal_id,
        proposal.proposal_id,
        new_key.key_id,
    ]
    assert all(event["recorded_at"] for event in events)

    # Governance events are recorded in the same durable replay log as
    # authorization/execution events, but do not corrupt decision reconstruction.
    assert service.boundary.replay_log.audit_summary()["decisions"] == {}
