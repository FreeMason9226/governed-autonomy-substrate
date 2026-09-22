from governed_autonomy import (
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
    health_report,
)


def test_health_report_covers_core_substrate_components():
    replay = ReplayLog()
    replay.append("frame-1", {"type": "authorization", "nonce": "n1"})
    registry = PolicyRegistry(
        (Policy("files-v1", ("read",), {}, {}),)
    )
    trust = TrustStore()
    trust.add("issuer", KeyPair.generate("issuer").public_key)

    report = health_report(
        replay_log=replay,
        trust_store=trust,
        policy_registry=registry,
    )

    assert report["ok"] is True
    assert report["checks"]["replay_chain"]["frames"] == 1
    assert report["checks"]["policy_registry"]["policies"] == 1
