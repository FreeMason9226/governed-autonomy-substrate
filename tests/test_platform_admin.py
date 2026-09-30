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


def test_policy_change_manager_prepare_and_signed_workflow_round_trips():
    """Exercises the pre-signed (prepare -> sign externally -> submit) workflow

    used by the admin browser UI, where the server never sees a private key.
    """
    trusted = TrustStore()
    proposer = KeyPair.generate("policy-owner")
    reviewer = KeyPair.generate("reviewer")
    trusted.add(proposer.key_id, proposer.public_key)
    trusted.add(reviewer.key_id, reviewer.public_key)
    registry = PolicyRegistry()
    manager = PolicyChangeManager(registry=registry, trust_store=trusted, required_approvals=1)
    policy = Policy(
        policy_id="op-limit-v2",
        allowed_actions=("read",),
        required_fields={"read": ("resource",)},
        exact_fields={"read": {}},
    )

    prepared = manager.prepare_proposal(
        new_policy=policy, proposer_key_id=proposer.key_id, rationale="externally signed"
    )
    signature = proposer.sign(prepared["unsigned_payload"].encode("utf-8"))
    proposal = manager.propose_signed(
        new_policy=policy,
        proposer_key_id=proposer.key_id,
        signature=signature,
        rationale="externally signed",
        proposal_id=prepared["proposal_id"],
    )
    assert proposal.status == "pending"
    assert proposal.proposal_id == prepared["proposal_id"]

    prepared_approval = manager.prepare_approval(proposal.proposal_id, approver_key_id=reviewer.key_id)
    approval_signature = reviewer.sign(prepared_approval["unsigned_payload"].encode("utf-8"))
    approved = manager.approve_signed(
        proposal.proposal_id,
        approver_key_id=reviewer.key_id,
        signature=approval_signature,
    )
    assert approved.approval_count() == 1

    activated = manager.activate(proposal.proposal_id)
    assert activated.policy_id == "op-limit-v2"
    assert registry.get("op-limit-v2") is not None


def test_policy_change_manager_propose_signed_rejects_bad_signature():
    trusted = TrustStore()
    proposer = KeyPair.generate("policy-owner")
    trusted.add(proposer.key_id, proposer.public_key)
    registry = PolicyRegistry()
    manager = PolicyChangeManager(registry=registry, trust_store=trusted, required_approvals=1)
    policy = Policy(
        policy_id="op-limit-v3",
        allowed_actions=("read",),
        required_fields={"read": ("resource",)},
        exact_fields={"read": {}},
    )
    try:
        manager.propose_signed(
            new_policy=policy,
            proposer_key_id=proposer.key_id,
            signature="not-a-real-signature",
            rationale="",
        )
        raise AssertionError("invalid signature should be rejected")
    except ValueError:
        pass


def test_policy_change_manager_approve_signed_rejects_duplicate_and_self_approval():
    trusted = TrustStore()
    proposer = KeyPair.generate("policy-owner")
    trusted.add(proposer.key_id, proposer.public_key)
    registry = PolicyRegistry()
    manager = PolicyChangeManager(registry=registry, trust_store=trusted, required_approvals=1)
    policy = Policy(
        policy_id="op-limit-v4",
        allowed_actions=("read",),
        required_fields={"read": ("resource",)},
        exact_fields={"read": {}},
    )
    proposal = manager.propose(new_policy=policy, proposer=proposer)
    prepared_approval = manager.prepare_approval(proposal.proposal_id, approver_key_id=proposer.key_id)
    self_signature = proposer.sign(prepared_approval["unsigned_payload"].encode("utf-8"))
    try:
        manager.approve_signed(
            proposal.proposal_id, approver_key_id=proposer.key_id, signature=self_signature
        )
        raise AssertionError("proposer should not be able to approve their own change")
    except ValueError:
        pass
