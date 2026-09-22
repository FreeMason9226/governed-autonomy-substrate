from governed_autonomy import DeterministicArbiter, GovernanceRuleTranslator, KeyPair, Policy, SignedApproval
from governed_autonomy.policy import policy_from_dict


def test_governance_rule_translator_builds_policy_from_human_rules():
    translator = GovernanceRuleTranslator(policy_id="ops-v1")
    policy = translator.translate(
        [
            "allow write_file when path is present and content is present",
            "require write_file tenant == 'acme'",
            "allow read_file when path == 'README.md'",
        ]
    )

    assert policy.policy_id == "ops-v1"
    assert policy.allowed_actions == ("read_file", "write_file")
    assert policy.required_fields["write_file"] == ("path", "content")
    assert policy.exact_fields["write_file"]["tenant"] == "acme"
    assert policy.exact_fields["read_file"]["path"] == "README.md"


def test_governance_rule_translator_merges_context_and_mapping_inputs():
    translator = GovernanceRuleTranslator(policy_id="ops-v2")
    policy = translator.translate(
        {
            "policy_id": "ops-v2",
            "required_context": ("tenant", "actor"),
            "exact_context": {"environment": "prod"},
            "rules": [
                {
                    "action": "deploy",
                    "required_fields": ["target", "image"],
                    "exact_fields": {"mode": "bluegreen"},
                    "required_context": ["tenant"],
                    "exact_context": {"environment": "prod"},
                }
            ],
        }
    )

    assert policy.required_context == ("actor", "tenant")
    assert policy.exact_context == {"environment": "prod"}
    assert policy.required_fields["deploy"] == ("target", "image")
    assert policy.exact_fields["deploy"]["mode"] == "bluegreen"


def test_governance_rule_translator_supports_approval_quorum_without_disabling_other_constraints():
    translator = GovernanceRuleTranslator(policy_id="ops-quorum")
    policy = translator.translate([
        "allow deploy when target is present and approvals >= 2",
        "require deploy tenant == 'acme'",
    ])

    assert policy.required_approvals == {"deploy": 2}
    assert policy.required_fields["deploy"] == ("target",)
    assert policy.exact_fields["deploy"]["tenant"] == "acme"

    alice = KeyPair.generate("approver-alice")
    bob = KeyPair.generate("approver-bob")
    request = {"action": "deploy", "target": "prod-us", "tenant": "acme"}
    decision = {"allow": True, "policy": "ops-quorum", "allowed_actions": ["deploy"]}
    approvals = [
        SignedApproval.from_request(
            request=request,
            decision=decision,
            issuer=alice,
            actor_id="alice",
        ).to_dict(),
        SignedApproval.from_request(
            request=request,
            decision=decision,
            issuer=bob,
            actor_id="bob",
        ).to_dict(),
    ]
    valid = DeterministicArbiter(
        issuer_keys={alice.key_id: alice.public_key, bob.key_id: bob.public_key}
    ).decide(
        {
            "action": "deploy",
            "target": "prod-us",
            "tenant": "acme",
            "approvals": approvals,
        },
        policy,
    )
    invalid = DeterministicArbiter(
        issuer_keys={alice.key_id: alice.public_key, bob.key_id: bob.public_key}
    ).decide(
        {
            "action": "deploy",
            "target": "prod-us",
            "tenant": "acme",
            "approvals": [approvals[0]],
        },
        policy,
    )

    assert valid["allow"] is True
    assert invalid["allow"] is False
    assert "approval_quorum_not_met" in invalid["reason_codes"]


def test_policy_supports_explicit_approval_thresholds_in_snapshot_roundtrip():
    policy = Policy(
        policy_id="ops-v3",
        allowed_actions=("deploy",),
        required_fields={"deploy": ("target",)},
        exact_fields={"deploy": {"tenant": "acme"}},
        required_approvals={"deploy": 3},
    )
    restored = policy_from_dict(policy.to_dict())

    assert restored.required_approvals == {"deploy": 3}
    assert restored.digest() == policy.digest()
