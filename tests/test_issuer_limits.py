import pytest

from governed_autonomy import AuthorizationIssuer, KeyPair, Policy, ReplayLog


def test_issuer_enforces_policy_maximum_ttl():
    policy = Policy(
        "short-v1",
        ("read",),
        {},
        {},
        max_ttl_seconds=10,
    )
    issuer = AuthorizationIssuer(
        issuer=KeyPair.generate(),
        replay_log=ReplayLog(),
        clock=lambda: 100,
        nonce_factory=lambda: "short-nonce",
    )

    with pytest.raises(ValueError, match="maximum"):
        issuer.authorize({"action": "read"}, policy, ttl_seconds=11)
