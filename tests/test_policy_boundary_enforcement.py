import time

import pytest

from governed_autonomy import (
    AuthorizationError,
    ExecutionBoundary,
    GovernanceAuthorizationArtifact,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
)


def test_execution_boundary_enforces_required_policy_fields_and_context():
    issuer = KeyPair.generate("boundary-issuer")
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy = Policy(
        "file-policy",
        ("write_file",),
        {"write_file": ("path", "content")},
        {"write_file": {"path": "out.txt"}},
        required_context=("tenant",),
        exact_context={"environment": "prod"},
    )
    registry = PolicyRegistry((policy,))
    request = {
        "action": "write_file",
        "path": "out.txt",
        "content": "hello",
        "context": {"tenant": "acme", "environment": "prod"},
    }
    decision = {
        "allow": True,
        "allowed_actions": ["write_file"],
        "policy": "file-policy",
        "policy_digest": policy.digest(),
        "reasons": [],
        "reason_codes": [],
    }
    artifact = GovernanceAuthorizationArtifact.issue(
        action_request=request,
        decision=decision,
        expires_at=int(time.time()) + 300,
        nonce="boundary-nonce-1",
        replay_frame_ref="authorization:boundary-nonce-1",
        issuer=issuer,
    )
    replay_log = ReplayLog()
    replay_log.append(
        "authorization:boundary-nonce-1",
        {
            "type": "authorization",
            "nonce": "boundary-nonce-1",
            "artifact_payload": artifact.unsigned_payload().decode("utf-8"),
            "issued": True,
        },
    )

    boundary = ExecutionBoundary(
        replay_log=replay_log,
        trust_store=trust_store,
        policy_registry=registry,
        clock=lambda: int(time.time()),
    )

    assert boundary.execute(artifact, lambda request: request["content"]) == "hello"

    tampered_request = {
        "action": "write_file",
        "path": "other.txt",
        "content": "hello",
        "context": {"tenant": "acme", "environment": "prod"},
    }
    tampered = GovernanceAuthorizationArtifact.issue(
        action_request=tampered_request,
        decision=decision,
        expires_at=artifact.expires_at,
        nonce="boundary-nonce-2",
        replay_frame_ref="authorization:boundary-nonce-2",
        issuer=issuer,
    )
    replay_log.append(
        "authorization:boundary-nonce-2",
        {
            "type": "authorization",
            "nonce": "boundary-nonce-2",
            "artifact_payload": tampered.unsigned_payload().decode("utf-8"),
            "issued": True,
        },
    )

    with pytest.raises(AuthorizationError, match="violates policy constraints"):
        boundary.execute(tampered, lambda request: pytest.fail("must not run"))
