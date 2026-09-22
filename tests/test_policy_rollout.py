import pytest

from governed_autonomy import KeyPair, Policy, PolicyRegistry, SignedPolicyManifest, TrustStore


def test_registry_rejects_policy_manifest_downgrade():
    issuer = KeyPair.generate("policy-authority")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    registry = PolicyRegistry()
    v1 = SignedPolicyManifest.issue(Policy("files-v1", ("read",), {}, {}), 1, issuer)
    v2 = SignedPolicyManifest.issue(Policy("files-v1", ("write",), {}, {}), 2, issuer)
    registry.register_signed(v2, trust)

    with pytest.raises(ValueError, match="stale"):
        registry.register_signed(v1, trust)


def test_registry_accepts_newer_policy_version_and_is_idempotent():
    issuer = KeyPair.generate("policy-authority")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    registry = PolicyRegistry()
    manifest = SignedPolicyManifest.issue(Policy("files-v1", ("read",), {}, {}), 1, issuer)
    registry.register_signed(manifest, trust)
    registry.register_signed(manifest, trust)

    assert registry.versions() == {"files-v1": 1}
