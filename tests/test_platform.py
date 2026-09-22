import pytest

from governed_autonomy import (
    GovernancePlatform,
    KeyPair,
    PlatformDeploymentPolicy,
    Policy,
    PolicyRegistry,
    ReplayLog,
    RuntimeIdentity,
    ServicePrincipal,
    ServicePrincipalRegistry,
    TrustStore,
    AuthorizationIssuer,
    ExecutionBoundary,
    GovernedService,
)


def test_platform_context_binds_runtime_identity_to_authorization_requests():
    issuer = KeyPair.generate("platform-issuer")
    replay_log = ReplayLog()
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy = Policy(
        policy_id="tenant-prod-v1",
        allowed_actions=("write_file",),
        required_fields={"write_file": ("path", "content")},
        exact_fields={"write_file": {"path": "out.txt"}},
        required_context=("actor_id", "environment", "tenant_id"),
        exact_context={"environment": "prod"},
    )
    registry = PolicyRegistry((policy,), trust_store=trust_store)
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=replay_log),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=registry,
        ),
        policies=registry,
        actions={"write_file": lambda request: request["content"]},
    )
    platform = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(
            service="files-api",
            environment="prod",
            tenant_id="tenant-a",
            actor_id="alice",
            request_id="req-123",
            source="internal-worker",
        ),
    )

    artifact = platform.authorize(
        {"action": "write_file", "path": "out.txt", "content": "ok"},
        "tenant-prod-v1",
    )

    assert artifact.action_request["context"]["tenant_id"] == "tenant-a"
    assert artifact.action_request["context"]["actor_id"] == "alice"
    assert artifact.action_request["context"]["environment"] == "prod"
    assert platform.platform_report()["service"] == "files-api"
    assert platform.platform_report()["health"]["ok"] is True


def test_platform_deployment_policy_rejects_unsafe_runtime_context():
    issuer = KeyPair.generate("platform-guard")
    replay_log = ReplayLog()
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy = Policy(
        policy_id="tenant-stage-v1",
        allowed_actions=("read_file",),
        required_fields={"read_file": ("path",)},
        exact_fields={"read_file": {}},
        required_context=("environment", "tenant_id"),
        exact_context={"environment": "staging"},
    )
    registry = PolicyRegistry((policy,), trust_store=trust_store)
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=replay_log),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=registry,
        ),
        policies=registry,
        actions={"read_file": lambda request: request["path"]},
    )
    platform = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(service="files-api", environment="staging", tenant_id="tenant-a"),
        deployment_policy=PlatformDeploymentPolicy(
            allowed_environments=("staging",),
            allowed_sources=("internal",),
            require_request_id=True,
            require_tenant=True,
            require_actor_id=True,
        ),
    )

    try:
        platform.authorize({"action": "read_file", "path": "/tmp/ok.txt"}, "tenant-stage-v1")
        raise AssertionError("expected deployment guard to reject a runtime without request/actor context")
    except ValueError as exc:
        assert "required" in str(exc)

    platform.authorize(
        {"action": "read_file", "path": "/tmp/ok.txt"},
        "tenant-stage-v1",
        context={"request_id": "req-4", "actor_id": "reviewer", "source": "internal"},
    )

    report = platform.platform_report()
    assert report["deployment"]["require_request_id"] is True
    assert report["deployment"]["allowed_environments"] == ["staging"]


def test_platform_service_principals_enforce_scope_and_roles():
    issuer = KeyPair.generate("platform-principal")
    replay_log = ReplayLog()
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy = Policy(
        policy_id="tenant-scope-v1",
        allowed_actions=("deploy",),
        required_fields={"deploy": ("target",)},
        exact_fields={"deploy": {}},
        required_context=("environment", "principal_id", "tenant_id"),
        exact_context={"environment": "prod"},
    )
    registry = PolicyRegistry((policy,), trust_store=trust_store)
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=replay_log),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=registry,
        ),
        policies=registry,
        actions={"deploy": lambda request: request["target"]},
    )
    principal_registry = ServicePrincipalRegistry(
        {
            "deploy-agent": ServicePrincipal(
                principal_id="deploy-agent",
                tenant_id="tenant-a",
                roles=("operator",),
                allowed_actions=("deploy",),
                allowed_environments=("prod",),
                allowed_sources=("internal-worker",),
                scope={"tenant_id": "tenant-a"},
            )
        }
    )
    platform = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(
            service="release-api",
            environment="prod",
            tenant_id="tenant-a",
            principal_id="deploy-agent",
            roles=("operator",),
            request_id="req-9",
            source="internal-worker",
        ),
        deployment_policy=PlatformDeploymentPolicy(
            allowed_environments=("prod",),
            allowed_sources=("internal-worker",),
            require_request_id=True,
            require_tenant=True,
            required_roles=("operator",),
        ),
        principal_registry=principal_registry,
    )

    artifact = platform.authorize({"action": "deploy", "target": "prod-cluster"}, "tenant-scope-v1")
    assert artifact.action_request["context"]["principal_id"] == "deploy-agent"
    assert artifact.action_request["context"]["roles"] == ["operator"]

    wrong_identity = RuntimeIdentity(
        service="release-api",
        environment="prod",
        tenant_id="tenant-b",
        principal_id="deploy-agent",
        roles=("operator",),
        request_id="req-10",
        source="internal-worker",
    )
    platform_wrong = GovernancePlatform(
        service=service,
        identity=wrong_identity,
        deployment_policy=platform.deployment_policy,
        principal_registry=principal_registry,
    )
    with pytest.raises(ValueError, match="tenant mismatch|missing tenant_id|unknown service principal"):
        platform_wrong.authorize({"action": "deploy", "target": "prod-cluster"}, "tenant-scope-v1")

    denied_registry = ServicePrincipalRegistry(
        {"deploy-agent": ServicePrincipal(principal_id="deploy-agent", tenant_id="tenant-a", roles=("operator",), allowed_actions=("read",))}
    )
    platform_denied = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(
            service="release-api",
            environment="prod",
            tenant_id="tenant-a",
            principal_id="deploy-agent",
            roles=("operator",),
            request_id="req-11",
            source="internal-worker",
        ),
        deployment_policy=platform.deployment_policy,
        principal_registry=denied_registry,
    )
    with pytest.raises(ValueError, match="not allowed for principal"):
        platform_denied.authorize({"action": "deploy", "target": "prod-cluster"}, "tenant-scope-v1")
