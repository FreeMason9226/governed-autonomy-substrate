import pytest

from governed_autonomy import GovernanceInput, GovernanceMesh, GovernanceMeshError, ReplayLog


def decision(allow, reason=None):
    value = {"allow": allow}
    if reason:
        value["reasons"] = [reason]
    return value


def test_mesh_preflight_is_deterministic_and_audited():
    inputs = [
        GovernanceInput("policy", decision(True), weight=3, priority=2),
        GovernanceInput("risk", decision(True), weight=1, priority=1),
    ]
    replay = ReplayLog()
    mesh = GovernanceMesh(replay_log=replay)
    first = mesh.preflight(inputs, request_digest="req-digest")
    second = GovernanceMesh().preflight(list(reversed(inputs)), request_digest="req-digest")
    assert first.allow is True
    assert first.status == "allow"
    assert first.digest == second.digest
    assert first.replay_frame_ref == f"mesh-{first.digest}"
    assert replay.events("governance_preflight")[0]["decision_digest"] == first.digest


def test_mesh_fails_closed_on_high_priority_conflict():
    result = GovernanceMesh().preflight(
        [
            GovernanceInput("allow-source", decision(True), weight=5, priority=10),
            GovernanceInput("deny-source", decision(False, "risk"), weight=1, priority=10),
        ],
        request_digest="req-digest",
    )
    assert result.status == "conflict"
    assert result.allow is False
    assert len(result.conflicts) == 1
    assert result.selected_source_ids == ()


def test_mesh_same_priority_divergence_fails_closed_even_when_allow_matches():
    result = GovernanceMesh().preflight(
        [
            GovernanceInput("policy", decision(True, "policy-ok"), weight=5, priority=4),
            GovernanceInput("risk", decision(True, "risk-ok"), weight=1, priority=4),
        ],
        request_digest="req-digest",
    )
    assert result.status == "conflict"
    assert result.allow is False
    assert result.selected_source_ids == ()


def test_mesh_weighted_decision_is_stable_when_priorities_do_not_conflict():
    result = GovernanceMesh().preflight(
        [
            GovernanceInput("allow-a", decision(True), weight=4, priority=2),
            GovernanceInput("deny-b", decision(False), weight=1, priority=1),
        ],
        request_digest="req-digest",
    )
    assert result.status == "allow"
    assert result.selected_source_ids == ("allow-a",)


def test_mesh_rejects_invalid_or_duplicate_inputs():
    with pytest.raises(GovernanceMeshError):
        GovernanceInput("source", {"allow": "yes"})
    with pytest.raises(GovernanceMeshError):
        GovernanceInput("source", {"allow": True, "unsupported": {1, 2}})
    with pytest.raises(GovernanceMeshError):
        GovernanceMesh().preflight(
            [GovernanceInput("same", decision(True)), GovernanceInput("same", decision(True))],
            request_digest="req-digest",
        )
    with pytest.raises(GovernanceMeshError):
        GovernanceMesh().preflight([], request_digest="req-digest")


def test_mesh_replay_frame_reference_is_part_of_audited_result():
    result = GovernanceMesh().preflight(
        [GovernanceInput("policy", decision(False, "denied"))],
        request_digest="req-digest",
        replay_frame_ref="authorization-frame-1",
    )
    assert result.status == "deny"
    assert result.allow is False
    assert result.replay_frame_ref == "authorization-frame-1"
    assert result.reasons == ("denied",)
