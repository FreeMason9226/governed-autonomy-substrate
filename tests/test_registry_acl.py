import pytest

from governed_autonomy import KeyPair, Policy, PolicyRegistry, TrustStore
from governed_autonomy.platform_admin import PolicyChangeManager


def test_hardened_registry_rejects_direct_execution_node_mutation():
    initial = Policy("files-v1", ("read",), {}, {})
    registry = PolicyRegistry((initial,), governance_admin_only=True)
    with pytest.raises(PermissionError, match="governance-admin"):
        registry.register(Policy("files-v2", ("write",), {}, {}), actor_role="execution-node")


def test_hardened_registry_requires_signed_multi_party_approval():
    proposer = KeyPair.generate("proposer")
    approver_a = KeyPair.generate("approver-a")
    approver_b = KeyPair.generate("approver-b")
    trust = TrustStore()
    for key in (proposer, approver_a, approver_b):
        trust.add(key.key_id, key.public_key)
    registry = PolicyRegistry(governance_admin_only=True, required_admin_approvals=2)
    manager = PolicyChangeManager(registry=registry, trust_store=trust, required_approvals=2)
    proposal = manager.propose(new_policy=Policy("files-v1", ("read",), {}, {}), proposer=proposer)
    manager.approve(proposal.proposal_id, approver=approver_a)
    with pytest.raises(ValueError, match="quorum"):
        manager.activate(proposal.proposal_id)
    manager.approve(proposal.proposal_id, approver=approver_b)
    assert manager.activate(proposal.proposal_id).policy_id == "files-v1"