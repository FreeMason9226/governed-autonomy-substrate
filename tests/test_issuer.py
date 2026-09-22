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
