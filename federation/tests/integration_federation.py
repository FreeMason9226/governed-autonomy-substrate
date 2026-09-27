from governed_autonomy import (
    GovernanceReconciler,
    GovernanceSyncEnvelope,
    KeyPair,
    Policy,
    PolicyRegistry,
    RegistrySnapshot,
    SignedPolicyManifest,
    SignedSyncEvent,
    TrustStore,
)


def test_two_independent_domains_cross_verify_signed_policy_and_frame():
    domain_a = KeyPair.generate("domain-a")
    domain_b = KeyPair.generate("domain-b")
    trust = TrustStore()
    trust.add(domain_a.key_id, domain_a.public_key)
    trust.add(domain_b.key_id, domain_b.public_key)
    remote = PolicyRegistry(trust_store=trust)
    policy = Policy("federated-read", ("read",), {"read": ("resource",)}, {})
    remote.register_signed(SignedPolicyManifest.issue(policy, 1, domain_b), trust)
    local = PolicyRegistry(trust_store=trust)
    snapshot = RegistrySnapshot.from_registry(remote, source_org="domain-b", version=1)
    event = SignedSyncEvent.issue(
        event_type="registry_update",
        source_org="domain-b",
        target_org="domain-a",
        snapshot_digest=snapshot.snapshot_digest,
        policy_digests=snapshot.policy_digests,
        nonce="federated-1",
        signer=domain_b,
        issued_at=100,
    )
    envelope = GovernanceSyncEnvelope.issue(event, snapshot, domain_b)
    result = GovernanceReconciler(
        local_org="domain-a",
        registry=local,
        trust_store=trust,
        organization_keys={"domain-b": domain_b.key_id},
        now=lambda: 100,
    ).reconcile(envelope)
    assert result.status == "adopted"
    assert local.get("federated-read").digest() == remote.get("federated-read").digest()