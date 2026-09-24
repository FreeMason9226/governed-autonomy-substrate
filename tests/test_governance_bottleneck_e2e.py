import pytest

from governed_autonomy import AuthorizationError, AuthorizationIssuer, ExecutionBoundary, KeyPair, Policy, ReplayLog


def test_governance_bottleneck_requires_valid_gaa_before_execution():
    issuer = KeyPair.generate("governance")
    replay = ReplayLog()
    policy = Policy("read-v1", ("read",), {"read": ()}, {})
    boundary = ExecutionBoundary(
        replay_log=replay,
        issuer_keys={issuer.key_id: issuer.public_key},
        clock=lambda: 100,
    )
    with pytest.raises(AuthorizationError, match="requires"):
        boundary.execute(None, lambda _: "must not run")

    artifact = AuthorizationIssuer(
        issuer=issuer, replay_log=replay, clock=lambda: 100, nonce_factory=lambda: "e2e-nonce"
    ).authorize({"action": "read"}, policy)
    assert boundary.execute(artifact, lambda _: "executed") == "executed"