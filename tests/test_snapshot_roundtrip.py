from governed_autonomy import KeyPair, Policy, PolicyRegistry, SignedPolicyManifest, TrustStore


def test_trust_and_policy_snapshots_round_trip():
    issuer = KeyPair.generate("snapshot-issuer")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)

    policy = Policy(
        "snapshot-policy",
        ("write_file",),
        {"write_file": ("path", "content")},
        {"write_file": {"path": "report.txt"}},
        required_context=("tenant",),
        exact_context={"environment": "prod"},
    )
    manifest = SignedPolicyManifest.issue(policy, 7, issuer)
    registry = PolicyRegistry(trust_store=trust)
    registry.register_signed(manifest, trust)

    snapshot = registry.to_dict()
    reloaded = PolicyRegistry.from_dict(snapshot, trust_store=trust)

    assert reloaded.get("snapshot-policy") == policy
    assert reloaded.versions() == {"snapshot-policy": 7}
    assert trust.to_dict()["keys"][issuer.key_id]
