import pytest

from governed_autonomy import (
    AuthorizationError,
    AuthorizationIssuer,
    ExecutionBoundary,
    KeyPair,
    Policy,
    ReplayLog,
)


def test_compensation_requires_failed_execution_and_is_audited():
    issuer = KeyPair.generate()
    log = ReplayLog()
    policy = Policy("repair-v1", ("repair",), {"repair": ("target",)}, {})
    auth = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        clock=lambda: 100,
        nonce_factory=iter(["original", "compensation"]).__next__,
    )
    original = auth.authorize({"action": "repair", "target": "item"}, policy)
    with pytest.raises(RuntimeError):
        ExecutionBoundary(
            replay_log=log,
            issuer_keys={issuer.key_id: issuer.public_key},
            clock=lambda: 100,
        ).execute(original, lambda _: (_ for _ in ()).throw(RuntimeError("failed")))

    compensation = auth.authorize_compensation(
        "original", {"action": "repair", "target": "item"}, policy
    )
    assert compensation.action_request["compensation_for"] == "original"


def test_compensation_rejects_nonce_without_failed_execution():
    auth = AuthorizationIssuer(
        issuer=KeyPair.generate(),
        replay_log=ReplayLog(),
        nonce_factory=lambda: "unused",
    )
    policy = Policy("repair-v1", ("repair",), {"repair": ("target",)}, {})
    with pytest.raises(AuthorizationError, match="failed execution"):
        auth.authorize_compensation(
            "missing", {"action": "repair", "target": "item"}, policy
        )
