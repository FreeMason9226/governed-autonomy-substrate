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
