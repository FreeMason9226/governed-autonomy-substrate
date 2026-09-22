from governed_autonomy import KeyPair, Policy, PolicyChangeManager, PolicyRegistry, TrustStore


def test_policy_change_manager_requires_quorum_before_activation():
    trusted = TrustStore()
    admin = KeyPair.generate("admin")
    reviewer_a = KeyPair.generate("reviewer-a")
    reviewer_b = KeyPair.generate("reviewer-b")
    trusted.add(admin.key_id, admin.public_key)
    trusted.add(reviewer_a.key_id, reviewer_a.public_key)
    trusted.add(reviewer_b.key_id, reviewer_b.public_key)

    registry = PolicyRegistry()
    manager = PolicyChangeManager(registry=registry, trust_store=trusted, required_approvals=2)
    new_policy = Policy(
        policy_id="deploy-v2",
        allowed_actions=("deploy",),
        required_fields={"deploy": ("image",)},
        exact_fields={"deploy": {"environment": "prod"}},
    )

    proposal = manager.propose(new_policy=new_policy, proposer=admin, rationale="roll out prod deploy policy")
    manager.approve(proposal.proposal_id, approver=reviewer_a)

    try:
        manager.activate(proposal.proposal_id)
        raise AssertionError("activation should require quorum")
    except ValueError:
        pass

    manager.approve(proposal.proposal_id, approver=reviewer_b)
    activated = manager.activate(proposal.proposal_id)

    assert activated.policy_id == "deploy-v2"
    assert registry.get("deploy-v2") is not None
    assert manager.get(proposal.proposal_id).status == "activated"


def test_policy_change_manager_rejects_tampered_proposals():
    trusted = TrustStore()
    proposer = KeyPair.generate("policy-owner")
    trusted.add(proposer.key_id, proposer.public_key)
    registry = PolicyRegistry()
    manager = PolicyChangeManager(registry=registry, trust_store=trusted, required_approvals=1)
    policy = Policy(
        policy_id="op-limit-v1",
        allowed_actions=("read",),
        required_fields={"read": ("resource",)},
        exact_fields={"read": {}},
    )

    proposal = manager.propose(new_policy=policy, proposer=proposer)
    tampered = proposal.__class__(
        proposal_id=proposal.proposal_id,
        policy_id=proposal.policy_id,
        current_policy_digest=proposal.current_policy_digest,
        proposed_policy=policy,
        proposed_by_key_id=proposal.proposed_by_key_id,
        rationale="tampered",
        status=proposal.status,
        signature="not-valid",
        approvals=proposal.approvals,
    )
    manager._proposals[proposal.proposal_id] = tampered

    try:
        manager.activate(proposal.proposal_id)
        raise AssertionError("tampered proposal should be rejected")
    except ValueError:
        pass
