from governed_autonomy import DeterministicArbiter, Policy


def test_policy_denies_request_over_configured_size_limit():
    policy = Policy(
        "small-v1",
        ("write",),
        {"write": ("content",)},
        {},
        max_request_bytes=64,
    )
    decision = DeterministicArbiter().decide(
        {"action": "write", "content": "x" * 100},
        policy,
    )

    assert decision["allow"] is False
    assert "request exceeds policy size limit" in decision["reasons"]


def test_policy_does_not_trust_caller_supplied_approval_count():
    policy = Policy(
        "approval-v1",
        ("deploy",),
        {"deploy": ("artifact",)},
        {},
        required_approvals={"deploy": 2},
    )

    decision = DeterministicArbiter().decide(
        {
            "action": "deploy",
            "artifact": "release.tgz",
            "approval_count": 2,
        },
        policy,
    )

    assert decision["allow"] is False
    assert "approval_quorum_not_met" in decision["reason_codes"]
