import pytest

from governed_autonomy import (
    FederationError,
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


def make_policy(policy_id: str, action: str = "read") -> Policy:
    return Policy(
        policy_id=policy_id,
        allowed_actions=(action,),
        required_fields={action: ("resource",)},
        exact_fields={action: {}},
    )


def make_fabric(local_policies=(), remote_policies=()):
    signer = KeyPair.generate("org-key")
    trust = TrustStore()
    trust.add(signer.key_id, signer.public_key)
    local = PolicyRegistry(tuple(local_policies), trust_store=trust)
    remote = PolicyRegistry(trust_store=trust)
    for policy in remote_policies:
        remote.register_signed(SignedPolicyManifest.issue(policy, 1, signer), trust)
    return signer, trust, local, remote


def envelope(signer, remote, *, source="org-b", target="org-a", nonce="n-1", issued_at=100):
    snapshot = RegistrySnapshot.from_registry(remote, source_org=source, version=1)
    event = SignedSyncEvent.issue(
        event_type="registry_update",
        source_org=source,
        target_org=target,
        snapshot_digest=snapshot.snapshot_digest,
        policy_digests=snapshot.policy_digests,
        nonce=nonce,
        signer=signer,
        issued_at=issued_at,
    )
    return GovernanceSyncEnvelope.issue(event, snapshot, signer)


def reconciler(local, trust, signer, now=100):
    return GovernanceReconciler(
        local_org="org-a",
        registry=local,
        trust_store=trust,
        organization_keys={"org-b": signer.key_id},
        now=lambda: now,
    )


def test_identical_signed_snapshot_is_a_noop():
    policy = make_policy("shared")
    signer, trust, _, remote = make_fabric(remote_policies=(policy,))
    local = PolicyRegistry(trust_store=trust)
    local.register_signed(SignedPolicyManifest.issue(policy, 1, signer), trust)
    result = reconciler(local, trust, signer).reconcile(envelope(signer, remote))
    assert result.status == "identical"
    assert result.imported_policy_ids == ()


def test_newer_remote_snapshot_adopts_signed_unknown_policy():
    signer, trust, local, remote = make_fabric(remote_policies=(make_policy("remote"),))
    result = reconciler(local, trust, signer).reconcile(envelope(signer, remote))
    assert result.status == "adopted"
    assert result.imported_policy_ids == ("remote",)
    assert local.get("remote").digest() == remote.get("remote").digest()


def test_conflicting_definition_is_reported_without_silent_merge():
    signer, trust, local, remote = make_fabric((make_policy("shared", "read"),), (make_policy("shared", "write"),))
    result = reconciler(local, trust, signer).reconcile(envelope(signer, remote))
    assert result.status == "conflict"
    assert result.conflicts[0]["policy_id"] == "shared"
    assert local.get("shared").allowed_actions == ("read",)


def test_invalid_signature_and_replayed_nonce_are_rejected():
    signer, trust, local, remote = make_fabric(remote_policies=(make_policy("remote"),))
    valid = envelope(signer, remote)
    tampered_event = SignedSyncEvent.from_dict({**valid.event.to_dict(), "target_org": "other"})
    tampered = GovernanceSyncEnvelope(valid.event, valid.snapshot, valid.signature)
    with pytest.raises(FederationError):
        reconciler(local, trust, signer).reconcile(GovernanceSyncEnvelope(tampered_event, valid.snapshot, valid.signature))

    fabric = reconciler(local, trust, signer)
    fabric.reconcile(valid)
    with pytest.raises(FederationError, match="nonce"):
        fabric.reconcile(valid)


def test_unknown_source_org_or_missing_trust_registration_is_rejected():
    signer, trust, local, remote = make_fabric(remote_policies=(make_policy("remote"),))
    valid = envelope(signer, remote, source="unknown")
    with pytest.raises(FederationError, match="unknown|registered"):
        reconciler(local, trust, signer).reconcile(valid)

    other = KeyPair.generate("untrusted-key")
    untrusted = envelope(other, remote)
    with pytest.raises(FederationError, match="unknown|registered|signature"):
        reconciler(local, trust, signer).reconcile(untrusted)


def test_multiple_policies_are_reconciled_and_applied_atomically_enough():
    policies = (make_policy("one"), make_policy("two", "write"), make_policy("three"))
    signer, trust, local, remote = make_fabric(remote_policies=policies)
    result = reconciler(local, trust, signer).reconcile(envelope(signer, remote))
    assert result.status == "adopted"
    assert result.imported_policy_ids == ("one", "three", "two")
    assert set(local.digests()) == {"one", "two", "three"}


def test_stale_event_timestamp_is_rejected():
    signer, trust, local, remote = make_fabric(remote_policies=(make_policy("remote"),))
    with pytest.raises(FederationError, match="stale"):
        reconciler(local, trust, signer, now=10_000).reconcile(envelope(signer, remote, issued_at=1))
