from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .observability import PlatformObservability
from .service import GovernedService


@dataclass(frozen=True)
class ServicePrincipal:
    """A bounded runtime identity for a service or worker, tied to a tenant and action scope."""

    principal_id: str
    tenant_id: str | None = None
    roles: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    allowed_environments: tuple[str, ...] = ()
    allowed_sources: tuple[str, ...] = ()
    scope: dict[str, Any] = field(default_factory=dict)


class ServicePrincipalRegistry:
    """Validates service identities before they can issue a signed governance decision."""

    def __init__(self, principals: dict[str, ServicePrincipal] | None = None) -> None:
        self._principals = dict(principals or {})

    def register(self, principal: ServicePrincipal) -> None:
        self._principals[principal.principal_id] = principal

    def get(self, principal_id: str) -> ServicePrincipal:
        try:
            return self._principals[principal_id]
        except KeyError as exc:  # pragma: no cover - explicit validation path
            raise ValueError(f"unknown service principal: {principal_id!r}") from exc

    def validate_runtime(
        self,
        *,
        identity: "RuntimeIdentity",
        action: str | None,
        context: dict[str, Any],
    ) -> None:
        if identity.principal_id is None:
            raise ValueError("principal_id is required when a service-principal registry is configured")

        principal = self.get(identity.principal_id)
        if principal.tenant_id is not None and identity.tenant_id is not None:
            if principal.tenant_id != identity.tenant_id:
                raise ValueError(
                    f"principal tenant mismatch for principal {identity.principal_id!r}: "
                    f"{principal.tenant_id!r} != {identity.tenant_id!r}"
                )
        if principal.tenant_id is not None and identity.tenant_id is None:
            raise ValueError("runtime identity is missing tenant_id for this service principal")

        if principal.allowed_actions and action is not None and action not in principal.allowed_actions:
            raise ValueError(f"action {action!r} is not allowed for principal {identity.principal_id!r}")

        environment = context.get("environment", identity.environment)
        if principal.allowed_environments and environment not in principal.allowed_environments:
            raise ValueError(
                f"environment {environment!r} is not permitted for principal {identity.principal_id!r}"
            )

        source = context.get("source", identity.source)
        if principal.allowed_sources and source is not None and source not in principal.allowed_sources:
            raise ValueError(f"source {source!r} is not permitted for principal {identity.principal_id!r}")

        if principal.scope and any(key not in context for key in principal.scope):
            missing = [key for key in principal.scope if key not in context]
            raise ValueError(f"service principal requires scope keys: {missing}")


@dataclass(frozen=True)
class PlatformDeploymentPolicy:
    """Runtime guardrails for environment and tenant separation."""

    allowed_environments: tuple[str, ...] = ("dev", "staging", "prod")
    allowed_sources: tuple[str, ...] = ("internal", "api", "worker", "scheduled", "manual")
    require_request_id: bool = True
    require_actor_id: bool = False
    require_tenant: bool = False
    required_roles: tuple[str, ...] = ()
    max_context_entries: int = 32

    def validate_runtime(self, *, identity: "RuntimeIdentity", context: dict[str, Any]) -> None:
        environment = context.get("environment", identity.environment)
        if environment not in self.allowed_environments:
            raise ValueError(f"environment is not allowed for this runtime: {environment!r}")

        tenant_id = context.get("tenant_id", identity.tenant_id)
        if self.require_tenant and not tenant_id:
            raise ValueError("tenant_id is required for this runtime configuration")

        actor_id = context.get("actor_id", identity.actor_id)
        if self.require_actor_id and not actor_id:
            raise ValueError("actor_id is required for this runtime configuration")

        request_id = context.get("request_id", identity.request_id)
        if self.require_request_id and not request_id:
            raise ValueError("request_id is required for this runtime configuration")

        source = context.get("source", identity.source)
        if source is not None and not any(
            source == allowed or source.startswith(f"{allowed}-")
            for allowed in self.allowed_sources
        ):
            raise ValueError(f"source is not allowed for this runtime: {source!r}")

        if self.required_roles:
            missing_roles = [role for role in self.required_roles if role not in identity.roles]
            if missing_roles:
                raise ValueError(f"identity is missing required roles: {missing_roles}")

        if len(context) > self.max_context_entries:
            raise ValueError("runtime context exceeds the allowed size")

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_environments": list(self.allowed_environments),
            "allowed_sources": list(self.allowed_sources),
            "require_request_id": self.require_request_id,
            "require_actor_id": self.require_actor_id,
            "require_tenant": self.require_tenant,
            "required_roles": list(self.required_roles),
            "max_context_entries": self.max_context_entries,
        }


@dataclass(frozen=True)
class RuntimeIdentity:
    """Identity and deployment context attached to governance decisions."""

    service: str
    environment: str = "dev"
    tenant_id: str | None = None
    actor_id: str | None = None
    request_id: str | None = None
    source: str | None = None
    principal_id: str | None = None
    roles: tuple[str, ...] = ()
    scope: dict[str, Any] = field(default_factory=dict)

    def context(self) -> dict[str, Any]:
        context: dict[str, Any] = dict(self.scope)
        if self.tenant_id is not None:
            context["tenant_id"] = self.tenant_id
        if self.actor_id is not None:
            context["actor_id"] = self.actor_id
        if self.environment is not None:
            context["environment"] = self.environment
        if self.request_id is not None:
            context["request_id"] = self.request_id
        if self.source is not None:
            context["source"] = self.source
        if self.principal_id is not None:
            context["principal_id"] = self.principal_id
        if self.roles:
            context["roles"] = list(self.roles)
        return context


class GovernancePlatform:
    """Platform layer that binds service identity and runtime context to the barrier."""

    def __init__(
        self,
        *,
        service: GovernedService,
        identity: RuntimeIdentity,
        observability: PlatformObservability | None = None,
        deployment_policy: PlatformDeploymentPolicy | None = None,
        principal_registry: ServicePrincipalRegistry | None = None,
    ) -> None:
        self.service = service
        self.identity = identity
        self.deployment_policy = deployment_policy or PlatformDeploymentPolicy()
        self.principal_registry = principal_registry
        self.observability = observability or PlatformObservability(
            service=service,
            service_name=identity.service,
            environment=identity.environment,
        )

    def authorize(
        self,
        request: dict[str, Any],
        policy_id: str,
        *,
        ttl_seconds: int = 300,
        approvals: list[Any] | None = None,
        context: dict[str, Any] | None = None,
    ):
        effective_request = dict(request)
        effective_context = dict(self.identity.context())
        if context:
            effective_context.update(context)
        effective_request.setdefault("context", {})
        effective_request["context"] = {**effective_context, **effective_request["context"]}
        if self.principal_registry is not None:
            self.principal_registry.validate_runtime(
                identity=self.identity,
                action=effective_request.get("action"),
                context=effective_request["context"],
            )
        self.deployment_policy.validate_runtime(identity=self.identity, context=effective_request["context"])
        try:
            artifact = self.service.authorize(
                effective_request,
                policy_id,
                ttl_seconds=ttl_seconds,
                approvals=approvals,
            )
            self.observability.record_authorized()
            return artifact
        except Exception:
            self.observability.record_denied()
            raise

    def execute(self, artifact):
        try:
            result = self.service.execute(artifact)
            self.observability.record_execution(ok=True)
            return result
        except Exception:
            self.observability.record_execution(ok=False)
            raise

    def platform_report(self) -> dict[str, Any]:
        report = {
            "service": self.identity.service,
            "environment": self.identity.environment,
            "tenant_id": self.identity.tenant_id,
            "actor_id": self.identity.actor_id,
            "request_id": self.identity.request_id,
            "principal_id": self.identity.principal_id,
            "roles": list(self.identity.roles),
            "health": self.service.audit_report()["health"],
            "policy_ids": sorted(self.service.policies.versions()),
            "actions": sorted(self.service.actions),
            "metrics": self.observability.snapshot()["metrics"],
            "deployment": self.deployment_policy.to_dict(),
        }
        return report
