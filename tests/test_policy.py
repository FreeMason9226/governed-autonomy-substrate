from governed_autonomy import DeterministicArbiter, Policy


def test_policy_decision_is_deterministic_and_allows_valid_request():
    policy = Policy(
        policy_id="files-v1",
        allowed_actions=("write_file",),
        required_fields={"write_file": ("path", "content")},
        exact_fields={"write_file": {"path": "out.txt"}},
    )
    request = {"action": "write_file", "path": "out.txt", "content": "ok"}
    arbiter = DeterministicArbiter()

    first = arbiter.decide(request, policy)
    second = arbiter.decide(dict(request), policy)

    assert first == second
    assert first["allow"] is True
    assert first["reasons"] == []
    assert first["reason_codes"] == []
    assert first["policy_digest"] == policy.digest()


def test_policy_digest_changes_when_constraints_change():
    base = Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {})
    changed = Policy(
        "files-v1",
        ("write_file",),
        {"write_file": ("path", "content")},
        {},
    )

    assert base.digest() != changed.digest()


def test_policy_rejects_unknown_action_and_reports_constraints():
    policy = Policy(
        policy_id="files-v1",
        allowed_actions=("write_file",),
        required_fields={"write_file": ("path", "content")},
        exact_fields={"write_file": {"path": "out.txt"}},
    )
    decision = DeterministicArbiter().decide(
        {"action": "delete_file", "path": "secret.txt"}, policy
    )

    assert decision["allow"] is False
    assert "action is not allowed by policy" in decision["reasons"]
    assert "action_not_allowed" in decision["reason_codes"]


def test_policy_rejects_missing_and_mismatched_fields():
    policy = Policy(
        policy_id="files-v1",
        allowed_actions=("write_file",),
        required_fields={"write_file": ("path", "content")},
        exact_fields={"write_file": {"path": "out.txt"}},
    )
    decision = DeterministicArbiter().decide(
        {"action": "write_file", "path": "other.txt"}, policy
    )

    assert decision["allow"] is False
    assert "required field is missing: content" in decision["reasons"]
    assert "field does not match policy: path" in decision["reasons"]
    assert "required_field_missing" in decision["reason_codes"]
    assert "field_mismatch" in decision["reason_codes"]


def test_policy_enforces_actor_and_scope_context():
    policy = Policy(
        "tenant-files-v1",
        ("write_file",),
        {"write_file": ("path", "content")},
        {},
        required_context=("actor_id", "tenant_id"),
        exact_context={"tenant_id": "tenant-a"},
    )
    arbiter = DeterministicArbiter()

    allowed = arbiter.decide(
        {
            "action": "write_file",
            "path": "out.txt",
            "content": "ok",
            "context": {"actor_id": "alice", "tenant_id": "tenant-a"},
        },
        policy,
    )
    denied = arbiter.decide(
        {
            "action": "write_file",
            "path": "out.txt",
            "content": "ok",
            "context": {"actor_id": "alice", "tenant_id": "tenant-b"},
        },
        policy,
    )

    assert allowed["allow"] is True
    assert denied["allow"] is False
    assert "context does not match policy: tenant_id" in denied["reasons"]
