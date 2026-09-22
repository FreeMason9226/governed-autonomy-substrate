import pytest

from governed_autonomy import (
    KeyPair,
    Policy,
    PolicyRegistry,
    SignedPolicyManifest,
    TrustStore,
    signed_policy_manifest_from_dict,
)


def test_signed_policy_manifest_round_trips_and_verifies():
    issuer = KeyPair.generate("policy-authority")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    policy = Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {})
    manifest = SignedPolicyManifest.issue(policy, 1, issuer)

    parsed = signed_policy_manifest_from_dict(manifest.to_dict())
    assert parsed == manifest
    assert parsed.verify(trust)


def test_registry_accepts_only_verified_signed_manifest():
    issuer = KeyPair.generate("policy-authority")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    registry = PolicyRegistry()
    manifest = SignedPolicyManifest.issue(
        Policy("files-v1", ("read",), {}, {}), 1, issuer
    )

    registry.register_signed(manifest, trust)
    assert registry.get("files-v1") == manifest.policy


def test_registry_rejects_untrusted_or_tampered_manifest():
    issuer = KeyPair.generate("policy-authority")
    trust = TrustStore()
    registry = PolicyRegistry()
    manifest = SignedPolicyManifest.issue(
        Policy("files-v1", ("read",), {}, {}), 1, issuer
    )

    with pytest.raises(ValueError, match="signature"):
        registry.register_signed(manifest, trust)
    trusted = TrustStore()
    trusted.add(issuer.key_id, issuer.public_key)
    tampered = SignedPolicyManifest(
        Policy("files-v1", ("write",), {}, {}),
        manifest.version,
        manifest.issuer_key_id,
        manifest.signature,
    )
    with pytest.raises(ValueError, match="signature"):
        registry.register_signed(tampered, trusted)


def test_registry_persists_and_reloads_signed_manifest(tmp_path):
    issuer = KeyPair.generate("policy-authority")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    path = tmp_path / "policy-registry.json"
    manifest = SignedPolicyManifest.issue(
        Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {}),
        2,
        issuer,
    )

    registry = PolicyRegistry(path=path, trust_store=trust)
    registry.register_signed(manifest, trust)

    reloaded = PolicyRegistry(path=path, trust_store=trust)
    assert reloaded.get("files-v1") == manifest.policy
    assert reloaded.versions() == {"files-v1": 2}
