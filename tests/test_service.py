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
