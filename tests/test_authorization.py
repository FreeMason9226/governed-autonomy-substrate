import time
from pathlib import Path

import pytest

from governed_autonomy import (
    AuthorizationError,
    ExecutionBoundary,
    GovernanceAuthorizationArtifact,
    KeyPair,
    ReplayLog,
    SQLiteReplayLog,
)


def setup_artifact(*, expires_at: int | None = None, allowed_actions=None):
    issuer = KeyPair.generate()
    log = ReplayLog()
    nonce = "nonce-1"
    request = {"action": "write_file", "path": "out.txt", "content": "ok"}
    decision = {
        "allow": True,
        "allowed_actions": allowed_actions or ["write_file"],
        "policy": "test-policy",
    }
    unsigned = GovernanceAuthorizationArtifact(
        request,
        decision,
        expires_at if expires_at is not None else int(time.time()) + 60,
        nonce,
        "authorization:nonce-1",
        issuer.key_id,
        "",
    )
    frame = log.append(
        "authorization:nonce-1",
        {
            "type": "authorization",
            "nonce": nonce,
            "artifact_payload": unsigned.unsigned_payload().decode(),
        },
    )
    artifact = GovernanceAuthorizationArtifact.issue(
        action_request=request,
        decision=decision,
        expires_at=unsigned.expires_at,
        nonce=nonce,
        replay_frame_ref=frame.frame_id,
        issuer=issuer,
    )
    boundary = ExecutionBoundary(
        replay_log=log,
        issuer_keys={issuer.key_id: issuer.public_key},
        clock=lambda: int(time.time()),
    )
    return artifact, boundary, log


def test_valid_execution_is_recorded():
    artifact, boundary, log = setup_artifact()
    assert boundary.execute(artifact, lambda request: request["content"]) == "ok"
    assert len(log.frames) == 2
    assert log.verify_chain()
    execution = log.get("execution:nonce-1")
    assert execution.event["result"] == "ok"
    assert execution.event["result_digest"]


def test_large_result_is_hashed_and_omitted_from_audit():
    artifact, boundary, log = setup_artifact()
    result = boundary.execute(artifact, lambda _: "x" * 5000)

    assert len(result) == 5000
    execution = log.get("execution:nonce-1")
    assert execution.event["result_omitted"] is True
    assert execution.event["result_omission_reason"] == "size-limit"
    assert execution.event["result_digest"]


def test_non_json_result_is_omitted_from_audit():
    artifact, boundary, log = setup_artifact()
    result = boundary.execute(artifact, lambda _: object())

    assert result is not None
    execution = log.get("execution:nonce-1")
    assert execution.event["result_omitted"] is True
    assert execution.event["result_omission_reason"] == "not-json"


@pytest.mark.parametrize(
    "mutator, message",
    [
        (lambda a: {**a.to_dict(), "action_request": {"action": "delete_file"}}, "signature"),
        (lambda a: {**a.to_dict(), "expires_at": 0}, "expired"),
        (lambda a: {**a.to_dict(), "replay_frame_ref": "missing"}, "signature"),
        (lambda a: {**a.to_dict(), "signature": ""}, "signature"),
    ],
)
def test_tampered_expired_replayed_or_unsigned_actions_are_rejected(mutator, message):
    artifact, boundary, log = setup_artifact()
    if message == "expired":
        artifact, boundary, log = setup_artifact(expires_at=0)
    elif message == "replay":
        artifact = GovernanceAuthorizationArtifact(
            **mutator(artifact)
        )
    else:
        artifact = GovernanceAuthorizationArtifact(**mutator(artifact))
    if message == "expired":
        with pytest.raises(AuthorizationError, match="expired"):
            boundary.execute(artifact, lambda _: "should not run")
    else:
        with pytest.raises(AuthorizationError, match="signature"):
            boundary.execute(artifact, lambda _: "should not run")

def test_replayed_action_is_rejected():
    artifact, boundary, _ = setup_artifact()
    boundary.execute(artifact, lambda _: "first")
    with pytest.raises(AuthorizationError, match="nonce"):
        boundary.execute(artifact, lambda _: "second")


def test_failed_action_is_still_consumed_before_invocation():
    artifact, boundary, log = setup_artifact()
    with pytest.raises(RuntimeError, match="action failed"):
        boundary.execute(
            artifact,
            lambda _: (_ for _ in ()).throw(RuntimeError("action failed")),
        )
    assert log.nonce_used(artifact.nonce)
    execution = log.get(f"execution:{artifact.nonce}")
    assert execution is not None
    assert execution.event["status"] == "failed"
    assert execution.event["error_type"] == "RuntimeError"
    with pytest.raises(AuthorizationError, match="nonce"):
        boundary.execute(artifact, lambda _: "must not retry")


def test_disallowed_action_is_rejected_before_callable_runs():
    artifact, boundary, _ = setup_artifact(allowed_actions=["read_file"])
    with pytest.raises(AuthorizationError, match="outside policy"):
        boundary.execute(artifact, lambda _: pytest.fail("action must not run"))


def test_missing_authorization_frame_is_rejected():
    artifact, boundary, log = setup_artifact()
    log._frames.clear()
    with pytest.raises(AuthorizationError, match="replay"):
        boundary.execute(artifact, lambda _: "should not run")


def test_sqlite_replay_log_survives_restart(tmp_path: Path):
    database = tmp_path / "replay.db"
    artifact, boundary, log = setup_artifact()
    durable = SQLiteReplayLog(database)
    for frame in log.frames:
        durable.append(frame.frame_id, frame.event)
    durable.close()

    reopened = SQLiteReplayLog(database)
    restarted_boundary = ExecutionBoundary(
        replay_log=reopened,
        issuer_keys=boundary.issuer_keys,
        clock=boundary.clock,
    )
    assert restarted_boundary.execute(artifact, lambda request: request["content"]) == "ok"
    reopened.close()

    final = SQLiteReplayLog(database)
    assert final.nonce_used(artifact.nonce)
    assert final.verify_chain()
    with pytest.raises(AuthorizationError, match="nonce"):
        ExecutionBoundary(
            replay_log=final,
            issuer_keys=boundary.issuer_keys,
            clock=boundary.clock,
        ).execute(artifact, lambda _: "duplicate")
    final.close()
