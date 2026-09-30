import datetime
import uuid
from collections.abc import Callable, Sequence
from typing import Any

from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .health import health_report
from .issuer import AuthorizationIssuer
from .mesh import GovernanceInput, GovernanceSourceRegistry
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .platform_admin import PolicyChangeManager, TrustChangeManager
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog


def _governance_audit_hook(replay_log: ReplayLog) -> Callable[[str, str], None]:
    """Record policy/trust governance lifecycle events in the durable replay log.

    Proposals, approvals, activations, and trust changes are otherwise only
    reflected as *current state* (the live proposal dict, the live trust
    store) with no historical record of who acted and when. Appending a
    ``"governance"``-typed frame per event gives that history the same
    durability and hash-chain tamper-evidence as authorization/execution
    events, without disturbing :meth:`ReplayLog.reconstruct_decisions` (which
    only inspects ``"authorization"``/``"execution"`` frames).
    """

    def hook(event: str, subject_id: str) -> None:
        replay_log.append(
            f"governance:{uuid.uuid4().hex}",
            {
                "type": "governance",
                "event": event,
                "subject_id": subject_id,
                "recorded_at": datetime.datetime.now(datetime.UTC).isoformat(),
            },
        )

    return hook


class GovernedService:
    """Application facade that binds authorized action names to safe handlers."""

    def __init__(
        self,
        *,
        issuer: AuthorizationIssuer,
        boundary: ExecutionBoundary,
        policies: PolicyRegistry | dict[str, Policy],
        actions: dict[str, Callable[[dict[str, Any]], Any]],
        mesh_source_registry: GovernanceSourceRegistry | None = None,
        policy_change_manager: PolicyChangeManager | None = None,
        trust_change_manager: TrustChangeManager | None = None,
    ) -> None:
        self.issuer = issuer
        self.boundary = boundary
        self.mesh_source_registry = mesh_source_registry
        self.policies = (
            policies
            if isinstance(policies, PolicyRegistry)
            else PolicyRegistry(tuple(policies.values()))
        )
        self.actions = dict(actions)
        governance_audit_hook = _governance_audit_hook(self.boundary.replay_log)
        if policy_change_manager is not None:
            self.policy_change_manager = policy_change_manager
        elif self.boundary.trust_store is not None:
            self.policy_change_manager = PolicyChangeManager(
                registry=self.policies,
                trust_store=self.boundary.trust_store,
                audit_hook=governance_audit_hook,
            )
        else:
            self.policy_change_manager = None
        if trust_change_manager is not None:
            self.trust_change_manager = trust_change_manager
        elif self.boundary.trust_store is not None:
            self.trust_change_manager = TrustChangeManager(
                trust_store=self.boundary.trust_store, audit_hook=governance_audit_hook
            )
        else:
            self.trust_change_manager = None

    def authorize(
        self,
        request: dict[str, Any],
        policy_id: str,
        *,
        ttl_seconds: int = 300,
        approvals: Sequence[SignedApproval | dict[str, Any]] | None = None,
        mesh_inputs: Sequence[GovernanceInput] | None = None,
    ) -> GovernanceAuthorizationArtifact:
        policy = self.policies.get(policy_id)
        if policy is None:
            raise AuthorizationError(f"unknown policy: {policy_id}")
        if self.mesh_source_registry is not None and self.issuer.mesh_source_registry is None:
            self.issuer.mesh_source_registry = self.mesh_source_registry
        return self.issuer.authorize(
            request,
            policy,
            ttl_seconds=ttl_seconds,
            approvals=approvals,
            mesh_inputs=mesh_inputs,
        )

    def execute(self, artifact: GovernanceAuthorizationArtifact) -> Any:
        action_name = artifact.action_request.get("action")
        action = self.actions.get(action_name)
        if action is None:
            raise AuthorizationError(f"unknown executable action: {action_name}")
        return self.boundary.execute(artifact, action)

    def execute_dict(self, value: dict[str, Any]) -> Any:
        """Execute a serialized GAA after strict parsing."""
        return self.execute(GovernanceAuthorizationArtifact.from_dict(value))

    def execute_json(self, value: str) -> Any:
        """Execute a canonical JSON GAA after strict parsing."""
        return self.execute(GovernanceAuthorizationArtifact.from_json(value))

    def governance_log(self) -> tuple[dict[str, Any], ...]:
        """Return the durable, hash-chained history of policy/trust governance actions.

        Each entry is a ``"governance"``-typed replay frame event (see
        :func:`_governance_audit_hook`): who proposed, approved, activated a
        policy change, or added/revoked a trusted key, and when. This is
        distinct from :meth:`audit_report`, which summarizes authorization
        and execution decisions, not governance lifecycle events.
        """
        return self.boundary.replay_log.events("governance")

    def audit_report(self) -> dict[str, Any]:
        """Return a deterministic summary of service policy, actions, health, and replay state."""
        return {
            "actions": sorted(self.actions),
            "policy_ids": sorted(self.policies.versions()),
            "policy_digests": self.policies.digests(),
            "audit_summary": self.boundary.replay_log.audit_summary(),
            "health": health_report(
                replay_log=self.boundary.replay_log,
                trust_store=self.boundary.trust_store,
                policy_registry=self.policies,
                mesh_source_registry=self.mesh_source_registry,
            ),
        }
