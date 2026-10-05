from __future__ import annotations

from typing import Any

from .crypto import KeyPair
from .mesh import GovernanceSourceRegistry
from .platform import (
    GovernancePlatform,
    PlatformDeploymentPolicy,
    RuntimeIdentity,
    ServicePrincipal,
    ServicePrincipalRegistry,
)
from .platform_admin import PolicyChangeManager, TrustChangeManager
from .policy import Policy, PolicyRegistry
from .service import GovernedService
from .trust import TrustStore


class ControlPlane:
    """High-level governance control plane for policy, trust, runtime, and mesh state.

    This façade keeps the operating-system-style orchestration of the patent MVP in one
    place: it exposes policy issuance, trust-key lifecycle, runtime registration, and a
    single place to inspect the health of the stack without reaching into every subsystem.
    """

    def __init__(
        self,
        *,
        trust_store: TrustStore | None = None,
        policy_registry: PolicyRegistry | None = None,
        mesh_source_registry: GovernanceSourceRegistry | None = None,
        deployment_policy: PlatformDeploymentPolicy | None = None,
        principal_registry: ServicePrincipalRegistry | None = None,
        services: dict[str, GovernedService | GovernancePlatform] | None = None,
    ) -> None:
        self.trust_store = trust_store or (policy_registry.trust_store if policy_registry else TrustStore())
        self.policy_registry = policy_registry or PolicyRegistry(trust_store=self.trust_store)
        self.mesh_source_registry = mesh_source_registry or GovernanceSourceRegistry()
        self.deployment_policy = deployment_policy or PlatformDeploymentPolicy()
        self.principal_registry = principal_registry or ServicePrincipalRegistry()
        self.services: dict[str, GovernancePlatform] = {}
        self.policy_change_manager = PolicyChangeManager(
            registry=self.policy_registry,
            trust_store=self.trust_store,
            required_approvals=1,
        )
        self.trust_change_manager = TrustChangeManager(trust_store=self.trust_store)
        self._register_services(services or {})

    def _register_services(
        self,
        services: dict[str, GovernedService | GovernancePlatform],
    ) -> None:
        for name, candidate in services.items():
            self.register_service(name, candidate)

    def register_service(
        self,
        name: str,
        service: GovernedService | GovernancePlatform,
        *,
        identity: RuntimeIdentity | None = None,
        deployment_policy: PlatformDeploymentPolicy | None = None,
        principal_registry: ServicePrincipalRegistry | None = None,
        mesh_source_registry: GovernanceSourceRegistry | None = None,
    ) -> GovernancePlatform:
        if not name:
            raise ValueError("service name must not be empty")
        if isinstance(service, GovernancePlatform):
            platform = service
        elif isinstance(service, GovernedService):
            platform = GovernancePlatform(
                service=service,
                identity=identity or RuntimeIdentity(service=name),
                deployment_policy=deployment_policy or self.deployment_policy,
                principal_registry=principal_registry or self.principal_registry,
                mesh_source_registry=mesh_source_registry or self.mesh_source_registry,
            )
        else:
            raise TypeError("service must be a GovernedService or GovernancePlatform instance")
        if platform.service.mesh_source_registry is None:
            platform.service.mesh_source_registry = mesh_source_registry or self.mesh_source_registry
        if platform.service.issuer.mesh_source_registry is None:
            platform.service.issuer.mesh_source_registry = mesh_source_registry or self.mesh_source_registry
        self.services[name] = platform
        return platform

    def register_trusted_key(self, key_id: str, public_key: Any) -> dict[str, Any]:
        self.trust_store.add(key_id, public_key)
        return self.trust_store.to_dict()

    def revoke_trusted_key(self, key_id: str) -> dict[str, Any]:
        self.trust_store.revoke(key_id)
        return self.trust_store.to_dict()

    def register_policy(self, policy: Policy) -> Policy:
        self.policy_registry.register(policy)
        return policy

    def propose_policy(
        self,
        *,
        policy: Policy,
        proposer: KeyPair,
        rationale: str = "",
        proposal_id: str | None = None,
        actor_id: str = "system",
    ) -> Any:
        return self.policy_change_manager.propose(
            new_policy=policy,
            proposer=proposer,
            rationale=rationale,
            proposal_id=proposal_id,
            actor_id=actor_id,
        )

    def approve_policy(
        self,
        proposal_id: str,
        *,
        approver: KeyPair,
        actor_id: str = "system",
    ) -> Any:
        return self.policy_change_manager.approve(
            proposal_id,
            approver=approver,
            actor_id=actor_id,
        )

    def activate_policy(self, proposal_id: str, *, actor_id: str = "system") -> Policy:
        return self.policy_change_manager.activate(proposal_id, actor_id=actor_id)

    def register_service_principal(self, principal: ServicePrincipal) -> ServicePrincipal:
        self.principal_registry.register(principal)
        return principal

    def register_mesh_source(self, source_id: str, public_key: Any) -> GovernanceSourceRegistry:
        self.mesh_source_registry.register(source_id, public_key)
        return self.mesh_source_registry

    def health(self, *, service_name: str | None = None) -> dict[str, Any]:
        if service_name is not None:
            platform = self.services[service_name]
            return {
                "service": service_name,
                "platform": platform.platform_report(),
                "trust_store": self.trust_store.to_dict(),
                "policies": self.policy_registry.digests(),
                "mesh_sources": self.mesh_source_registry.to_dict(),
            }

        services = {
            name: platform.platform_report() for name, platform in sorted(self.services.items())
        }
        return {
            "service_count": len(services),
            "services": services,
            "trust_store": self.trust_store.to_dict(),
            "policies": self.policy_registry.digests(),
            "mesh_sources": self.mesh_source_registry.to_dict(),
        }

    def snapshot(self) -> dict[str, Any]:
        return {
            "trust_store": self.trust_store.to_dict(),
            "policies": {
                policy_id: policy.to_dict() for policy_id, policy in sorted(self.policy_registry._policies.items())
            },
            "mesh_sources": self.mesh_source_registry.to_dict(),
            "services": {
                name: platform.platform_report() for name, platform in sorted(self.services.items())
            },
            "proposals": [
                proposal.to_summary_dict()
                for proposal in self.policy_change_manager.proposals()
            ],
        }


def build_control_plane(
    *,
    trust_store: TrustStore | None = None,
    policy_registry: PolicyRegistry | None = None,
    mesh_source_registry: GovernanceSourceRegistry | None = None,
    deployment_policy: PlatformDeploymentPolicy | None = None,
    principal_registry: ServicePrincipalRegistry | None = None,
    services: dict[str, GovernedService | GovernancePlatform] | None = None,
) -> ControlPlane:
    return ControlPlane(
        trust_store=trust_store,
        policy_registry=policy_registry,
        mesh_source_registry=mesh_source_registry,
        deployment_policy=deployment_policy,
        principal_registry=principal_registry,
        services=services,
    )
