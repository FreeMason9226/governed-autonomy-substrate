import pytest

from governed_autonomy import GovernanceAuthorizationArtifact, KeyPair, SignedApproval


def test_artifact_round_trips_through_transport_dict():
    issuer = KeyPair.generate()
    artifact = GovernanceAuthorizationArtifact.issue(
        action_request={"action": "read"},
        decision={"allow": True, "allowed_actions": ["read"]},
        expires_at=100,
        nonce="nonce",
        replay_frame_ref="authorization:nonce",
        issuer=issuer,
    )

    assert GovernanceAuthorizationArtifact.from_dict(artifact.to_dict()) == artifact
    assert GovernanceAuthorizationArtifact.from_json(artifact.to_json()) == artifact


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: {**value, "signature": 123},
        lambda value: {**value, "expires_at": True},
        lambda value: {**value, "decision": []},
        lambda value: {**value, "extra": "rejected"},
        lambda value: {key: item for key, item in value.items() if key != "nonce"},
    ],
)
def test_artifact_parser_rejects_malformed_transport(mutator):
    issuer = KeyPair.generate()
    artifact = GovernanceAuthorizationArtifact.issue(
        action_request={"action": "read"},
        decision={"allow": True, "allowed_actions": ["read"]},
        expires_at=100,
        nonce="nonce",
        replay_frame_ref="authorization:nonce",
        issuer=issuer,
    )

    with pytest.raises(ValueError):
        GovernanceAuthorizationArtifact.from_dict(mutator(artifact.to_dict()))


def test_artifact_json_parser_rejects_invalid_json():
    with pytest.raises(ValueError, match="invalid"):
        GovernanceAuthorizationArtifact.from_json("{not-json")


def test_signed_approval_round_trips_and_verifies():
    issuer = KeyPair.generate("approver-1")
    approval = SignedApproval.issue(
        action="deploy",
        request_digest="abc123",
        decision_digest="def456",
        issuer=issuer,
        actor_id="alice",
        context={"tenant_id": "tenant-a"},
    )

    assert SignedApproval.from_dict(approval.to_dict()) == approval
    assert approval.verify(issuer.public_key) is True


def test_signed_approvals_count_toward_quorum_only_when_signature_is_valid():
    alice = KeyPair.generate("approver-a")
    bob = KeyPair.generate("approver-b")
    request = {"action": "deploy", "target": "prod-us"}
    decision = {"allow": True, "allowed_actions": ["deploy"], "policy": "deploy-v1"}
    policy = SignedApproval.from_request(
        request=request,
        decision=decision,
        issuer=alice,
        actor_id="alice",
    )
    valid_bob = SignedApproval.from_request(
        request=request,
        decision=decision,
        issuer=bob,
        actor_id="bob",
    )
    tampered = SignedApproval.from_dict({**valid_bob.to_dict(), "signature": "bad"})

    request_with_approvals = {
        "action": "deploy",
        "target": "prod-us",
        "approvals": [policy.to_dict(), valid_bob.to_dict()],
    }
    bad_request = {
        "action": "deploy",
        "target": "prod-us",
        "approvals": [policy.to_dict(), tampered.to_dict()],
    }

    from governed_autonomy import DeterministicArbiter, Policy

    quorum_policy = Policy(
        policy_id="deploy-v1",
        allowed_actions=("deploy",),
        required_fields={"deploy": ("target",)},
        exact_fields={"deploy": {}},
        required_approvals={"deploy": 2},
    )
    good = DeterministicArbiter(issuer_keys={alice.key_id: alice.public_key, bob.key_id: bob.public_key}).decide(request_with_approvals, quorum_policy)
    bad = DeterministicArbiter(issuer_keys={alice.key_id: alice.public_key, bob.key_id: bob.public_key}).decide(bad_request, quorum_policy)

    assert good["allow"] is True
    assert bad["allow"] is False
    assert "approval_quorum_not_met" in bad["reason_codes"]


def test_signed_approval_rejects_requests_with_mismatched_digest_or_action():
    issuer = KeyPair.generate("approver")
    request = {"action": "deploy", "target": "prod-us"}
    approval = SignedApproval.from_request(request=request, decision={"allow": True}, issuer=issuer)

    assert approval.matches_request(request) is True
    assert approval.matches_request({"action": "deploy", "target": "prod-eu"}) is False
    assert approval.matches_request({"action": "read", "target": "prod-us"}) is False
