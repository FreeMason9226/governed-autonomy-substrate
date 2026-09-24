from __future__ import annotations

from governed_autonomy import (
    ComplianceAuditor,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
)
from governed_autonomy.replay import ReplayFrame


def test_compliance_auditor_clean_pass() -> None:
    key = KeyPair.generate("test-key")
    trust = TrustStore()
    trust.add(key.key_id, key.public_key)

    policy = Policy(
        policy_id="test-pol",
        allowed_actions=("read",),
        required_fields={},
        exact_fields={},
        required_approvals={"read": 1},
    )
    registry = PolicyRegistry((policy,))
    replay = ReplayLog()
    replay.append("frame-001", {"type": "genesis"})

    auditor = ComplianceAuditor(
        replay_log=replay,
        trust_store=trust,
        policy_registry=registry,
    )

    report = auditor.generate_report()
    assert report["compliance_status"] == "COMPLIANT"
    assert report["score"]["failed"] == 0
    assert len(report["nist_ai_rmf"]) >= 4
    assert len(report["eu_ai_act"]) >= 4


def test_compliance_auditor_detects_chain_break() -> None:
    key = KeyPair.generate("test-key")
    trust = TrustStore()
    trust.add(key.key_id, key.public_key)

    replay = ReplayLog()
    # Inject bad frame directly
    bad_frame = ReplayFrame(
        frame_id="bad-1",
        previous_hash="wrong_hash",
        event={"type": "tampered"},
        frame_hash="abc",
    )
    replay._frames.append(bad_frame)

    auditor = ComplianceAuditor(
        replay_log=replay,
        trust_store=trust,
    )

    report = auditor.generate_report()
    assert report["compliance_status"] == "NON_COMPLIANT"
    assert report["score"]["failed"] >= 1
    # Both NIST MS-3.2 and EU AI Act Article 12 should fail
    nist_failures = [e for e in report["nist_ai_rmf"] if e["status"] == "FAIL"]
    assert any(e["control_id"] == "MS-3.2" for e in nist_failures)


def test_empty_policy_registry_is_not_reported_as_active() -> None:
    key = KeyPair.generate("test-key")
    trust = TrustStore()
    trust.add(key.key_id, key.public_key)
    replay = ReplayLog()

    auditor = ComplianceAuditor(
        replay_log=replay,
        trust_store=trust,
        policy_registry=PolicyRegistry(),
    )

    article_nine = next(
        result
        for result in auditor.evaluate_eu_ai_act()
        if result.control_id == "Article 9"
    )
    assert article_nine.status == "WARNING"
