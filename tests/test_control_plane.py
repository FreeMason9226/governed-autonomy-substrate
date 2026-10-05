from governed_autonomy import ControlPlane
from governed_autonomy.crypto import KeyPair
from governed_autonomy.mesh import GovernanceSourceRegistry
from governed_autonomy.platform import ServicePrincipal
from governed_autonomy.policy import Policy


def test_control_plane_tracks_trust_and_policies() -> None:
    cp = ControlPlane()
    operator = KeyPair.generate("control-plane-operator")

    cp.register_trusted_key(operator.key_id, operator.public_key)
    policy = Policy(
        policy_id="control-plane-policy",
        allowed_actions=("deploy",),
        required_fields={"deploy": ("tenant_id",)},
        exact_fields={},
    )
    cp.register_policy(policy)

    snapshot = cp.snapshot()
    assert snapshot["trust_store"]["keys"][operator.key_id]
    assert snapshot["policies"]["control-plane-policy"]["policy_id"] == "control-plane-policy"


def test_control_plane_policy_workflow() -> None:
    cp = ControlPlane()
    proposer = KeyPair.generate("policy-proposer")
    approver = KeyPair.generate("policy-approver")
    cp.register_trusted_key(proposer.key_id, proposer.public_key)
    cp.register_trusted_key(approver.key_id, approver.public_key)

    policy = Policy(
        policy_id="governed-deploy",
        allowed_actions=("deploy",),
        required_fields={"deploy": ("target",)},
        exact_fields={},
    )
    proposal = cp.propose_policy(policy=policy, proposer=proposer, rationale="ready for activation")
    cp.approve_policy(proposal.proposal_id, approver=approver)
    activated = cp.activate_policy(proposal.proposal_id)

    assert activated.policy_id == "governed-deploy"
    assert cp.policy_registry.get("governed-deploy") is policy


def test_control_plane_registers_mesh_and_principal_state() -> None:
    cp = ControlPlane()
    source = KeyPair.generate("mesh-source")
    cp.register_mesh_source("mesh-source", source.public_key)
    cp.register_service_principal(
        ServicePrincipal(
            principal_id="svc-a",
            tenant_id="tenant-a",
            roles=("ops",),
            allowed_actions=("deploy",),
            allowed_environments=("prod",),
        )
    )

    health = cp.health()
    assert len(health["mesh_sources"]["sources"]) == 1
    assert health["mesh_sources"]["revoked"] == []
    assert health["service_count"] == 0
    assert cp.principal_registry.get("svc-a").tenant_id == "tenant-a"
