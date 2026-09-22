import pytest

from governed_autonomy import (
    AuthorizationError,
    AuthorizationIssuer,
    ExecutionBoundary,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
)


def test_boundary_rejects_stale_registered_policy_digest():
    issuer = KeyPair.generate()
    log = ReplayLog()
    original = Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {})
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "policy-nonce",
    ).authorize({"action": "write_file", "path": "out.txt"}, original)
    changed = Policy(
        "files-v1",
        ("write_file",),
        {"write_file": ("path", "content")},
        {},
    )

    with pytest.raises(AuthorizationError, match="digest"):
        ExecutionBoundary(
            replay_log=log,
            issuer_keys={issuer.key_id: issuer.public_key},
            policy_registry=PolicyRegistry((changed,)),
        ).execute(artifact, lambda _: "must not run")


def test_boundary_accepts_matching_registered_policy():
    issuer = KeyPair.generate()
    log = ReplayLog()
    policy = Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {})
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "policy-nonce",
    ).authorize({"action": "write_file", "path": "out.txt"}, policy)

    assert ExecutionBoundary(
        replay_log=log,
        issuer_keys={issuer.key_id: issuer.public_key},
        policy_registry=PolicyRegistry((policy,)),
    ).execute(artifact, lambda _: "ok") == "ok"
