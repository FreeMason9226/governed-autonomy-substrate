import json
from pathlib import Path

import pytest

from governed_autonomy import ReplayLog
from governed_autonomy.replay import ReplayFrame


def test_jsonl_replay_log_reloads_consumed_nonces(tmp_path: Path):
    path = tmp_path / "replay.jsonl"
    log = ReplayLog(path)
    log.append("authorization:n1", {"type": "authorization", "nonce": "n1"})
    log.mark_nonce("n1")
    log.append(
        "execution:n1",
        {"type": "execution", "nonce": "n1", "status": "completed", "result": "ok"},
    )

    recovered = ReplayLog.load_jsonl(path)

    assert len(recovered.frames) == 2
    assert recovered.nonce_used("n1")
    assert recovered.verify_chain()


def test_jsonl_recovery_rejects_tampered_frame(tmp_path: Path):
    path = tmp_path / "replay.jsonl"
    log = ReplayLog(path)
    log.append("frame-1", {"type": "authorization", "nonce": "n1"})
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["event"]["nonce"] = "attacker-nonce"
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="frame hash"):
        ReplayLog.load_jsonl(path)


def test_jsonl_recovery_rejects_broken_chain(tmp_path: Path):
    path = tmp_path / "replay.jsonl"
    log = ReplayLog(path)
    log.append("frame-1", {"type": "authorization", "nonce": "n1"})
    log.append("frame-2", {"type": "authorization", "nonce": "n2"})
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[1]["previous_hash"] = ""
    rows[1]["frame_hash"] = ReplayFrame.create(
        rows[1]["frame_id"], "", rows[1]["event"]
    ).frame_hash
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="frame hash|chain"):
        ReplayLog.load_jsonl(path)


def test_replay_log_reconstructs_authorization_history():
    log = ReplayLog()
    log.append(
        "authorization:n1",
        {
            "type": "authorization",
            "nonce": "n1",
            "request": {"action": "write_file"},
            "decision": {"allow": True, "policy": "demo-v1"},
            "issued": True,
        },
    )
    log.append(
        "execution:n1",
        {
            "type": "execution",
            "nonce": "n1",
            "status": "completed",
            "result": {"ok": True},
        },
    )

    summary = log.audit_summary()
    reconstructed = log.reconstruct_decisions()

    assert summary["authorization_count"] == 1
    assert summary["execution_count"] == 1
    assert summary["success_count"] == 1
    assert reconstructed["n1"]["authorization"]["issued"] is True
    assert reconstructed["n1"]["execution"]["status"] == "completed"
