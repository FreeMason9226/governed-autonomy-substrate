import pytest

from governed_autonomy import (
    AuthorizationIssuer,
    DeterministicArbiter,
    ExecutionBoundary,
    KeyPair,
    Policy,
    PolicyDeniedError,
    ReplayLog,
    SignedApproval,
    AuthorizationError,
    GovernanceInput,
    GovernanceMesh,
)


def policy() -> Policy:
    return Policy(
        policy_id="files-v1",
        allowed_actions=("write_file",),
        required_fields={"write_file": ("path", "content")},
        exact_fields={"write_file": {"path": "out.txt"}},
    )


def test_issuer_creates_audited_artifact_accepted_by_boundary():
    issuer = KeyPair.generate()
    log = ReplayLog()
    authorization = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "fixed-nonce",
    ).authorize({"action": "write_file", "path": "out.txt", "content": "ok"}, policy())

    result = ExecutionBoundary(
        replay_log=log,
        issuer_keys={issuer.key_id: issuer.public_key},
        clock=lambda: 100,
    ).execute(authorization, lambda request: request["content"])

    assert result == "ok"
    assert log.get("authorization:fixed-nonce").event["issued"] is True


def test_denied_request_is_audited_and_never_issued():
    log = ReplayLog()
    with pytest.raises(PolicyDeniedError) as raised:
        AuthorizationIssuer(
            issuer=KeyPair.generate(),
            replay_log=log,
            nonce_factory=lambda: "denied-nonce",
        ).authorize({"action": "delete_file", "path": "secret.txt"}, policy())

    assert raised.value.decision["allow"] is False
    frame = log.get("authorization:denied-nonce")
    assert frame is not None
    assert frame.event["issued"] is False


def test_issuer_accepts_signed_approvals_for_quorum_and_rejects_tampered_evidence():
    issuer = KeyPair.generate("issuer")
    approver_a = KeyPair.generate("approver-a")
    approver_b = KeyPair.generate("approver-b")
    quorum_policy = Policy(
        policy_id="quorum-v1",
        allowed_actions=("write_file",),
        required_fields={"write_file": ("path", "content")},
        exact_fields={"write_file": {"path": "out.txt"}},
        required_approvals={"write_file": 2},
    )
    request = {"action": "write_file", "path": "out.txt", "content": "ok"}
    decision = {"allow": True, "allowed_actions": ["write_file"], "policy": "quorum-v1"}
    approvals = [
        SignedApproval.from_request(
            request=request,
            decision=decision,
            issuer=approver_a,
            actor_id="alice",
        ),
        SignedApproval.from_request(
            request=request,
            decision=decision,
            issuer=approver_b,
            actor_id="bob",
        ),
    ]

    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=ReplayLog(),
        nonce_factory=lambda: "quorum-nonce",
        arbiter=DeterministicArbiter(
            issuer_keys={
                approver_a.key_id: approver_a.public_key,
                approver_b.key_id: approver_b.public_key,
            }
        ),
    ).authorize(
        request,
        quorum_policy,
        approvals=approvals,
    )

    assert artifact.action_request["approvals"][0]["issuer_key_id"] == approver_a.key_id
    with pytest.raises(PolicyDeniedError):
        AuthorizationIssuer(
            issuer=issuer,
            replay_log=ReplayLog(),
            nonce_factory=lambda: "bad-quorum-nonce",
            arbiter=DeterministicArbiter(
                issuer_keys={
                    approver_a.key_id: approver_a.public_key,
                    approver_b.key_id: approver_b.public_key,
                }
            ),
        ).authorize(
            request,
            quorum_policy,
            approvals=[approvals[0], {**approvals[1].to_dict(), "signature": "not-valid"}],
        )


def test_issuer_binds_allow_mesh_preflight_into_signed_decision_and_replay():
    from governed_autonomy import GovernanceInput, GovernanceMesh

    issuer = KeyPair.generate("mesh-issuer")
    log = ReplayLog()
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "mesh-nonce",
        mesh=GovernanceMesh(replay_log=log),
    ).authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        policy(),
        mesh_inputs=[GovernanceInput("policy-source", {"allow": True}, priority=5)],
    )

    assert artifact.decision["mesh_preflight_digest"]
    assert log.events("governance_preflight")[0]["decision_digest"] == artifact.decision["mesh_preflight_digest"]
    assert log.get("authorization:mesh-nonce").event["artifact_payload"] == artifact.unsigned_payload().decode()


def test_issuer_rejects_denied_mesh_preflight_before_issuing_gaa():
    from governed_autonomy import GovernanceInput, GovernanceMesh

    log = ReplayLog()
    with pytest.raises(PolicyDeniedError) as raised:
        AuthorizationIssuer(
            issuer=KeyPair.generate("mesh-deny"),
            replay_log=log,
            nonce_factory=lambda: "mesh-denied-nonce",
            mesh=GovernanceMesh(replay_log=log),
        ).authorize(
            {"action": "write_file", "path": "out.txt", "content": "ok"},
            policy(),
            mesh_inputs=[GovernanceInput("risk-source", {"allow": False, "reasons": ["risk"]})],
        )

    assert "governance_mesh_denied" in raised.value.decision["reason_codes"]
    assert raised.value.decision["mesh_preflight_digest"]
    assert log.get("authorization:mesh-denied-nonce").event["issued"] is False


def test_execution_reconstructs_mesh_evidence_before_running_action():
    issuer = KeyPair.generate("mesh-execution")
    log = ReplayLog()
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "mesh-execution-nonce",
        mesh=GovernanceMesh(replay_log=log),
    ).authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        policy(),
        mesh_inputs=[GovernanceInput("policy-source", {"allow": True}, priority=5)],
    )

    result = ExecutionBoundary(
        replay_log=log,
        issuer_keys={issuer.key_id: issuer.public_key},
        clock=lambda: 100,
    ).execute(artifact, lambda request: request["content"])
    assert result == "ok"


def test_issuer_accepts_mesh_source_registry_for_preflight_verified_authorization():
    from governed_autonomy import GovernanceSourceRegistry

    issuer = KeyPair.generate("mesh-registry-issuer")
    source = KeyPair.generate("policy-source")
    registry = GovernanceSourceRegistry()
    registry.register("policy-source", source.public_key)

    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=ReplayLog(),
        nonce_factory=lambda: "mesh-registry-nonce",
        mesh_source_registry=registry,
    ).authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        policy(),
        mesh_inputs=[GovernanceInput("policy-source", {"allow": True}, priority=5).attest(source)],
    )

    assert artifact.decision["mesh_preflight_digest"]


@pytest.mark.parametrize(
    "tamper",
    [
        lambda event: event["mesh_inputs"][0]["decision"].update({"allow": False}),
        lambda event: event.update({"mesh_preflight_digest": "wrong"}),
        lambda event: event.update({"mesh_inputs": [{"source_id": "bad"}]}),
        lambda event: event["mesh_inputs"].append(event["mesh_inputs"][0].copy()),
        lambda event: event.update({"mesh_request_digest": "wrong"}),
    ],
)
def test_execution_rejects_tampered_or_invalid_mesh_evidence(tamper):
    issuer = KeyPair.generate()
    log = ReplayLog()
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "tampered-mesh-nonce",
    ).authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        policy(),
        mesh_inputs=[GovernanceInput("policy-source", {"allow": True})],
    )
    tamper(log.get("authorization:tampered-mesh-nonce").event)

    with pytest.raises(AuthorizationError):
        ExecutionBoundary(
            replay_log=log,
            issuer_keys={issuer.key_id: issuer.public_key},
            clock=lambda: 100,
        ).execute(artifact, lambda request: request["content"])


def test_legacy_artifact_without_mesh_evidence_still_executes():
    issuer = KeyPair.generate("legacy")
    log = ReplayLog()
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "legacy-nonce",
    ).authorize({"action": "write_file", "path": "out.txt", "content": "ok"}, policy())
    assert ExecutionBoundary(
        replay_log=log,
        issuer_keys={issuer.key_id: issuer.public_key},
        clock=lambda: 100,
    ).execute(artifact, lambda request: request["content"]) == "ok"
