import sqlite3
from pathlib import Path

import pytest

from governed_autonomy import SQLiteReplayLog


def test_sqlite_recovery_fails_closed_on_tampered_frame(tmp_path: Path):
    path = tmp_path / "replay.db"
    log = SQLiteReplayLog(path)
    log.append("frame-1", {"type": "authorization", "nonce": "n1"})
    log.close()

    connection = sqlite3.connect(path)
    connection.execute(
        "UPDATE replay_frames SET event_json = ? WHERE frame_id = ?",
        ('{"nonce":"attacker","type":"authorization"}', "frame-1"),
    )
    connection.commit()
    connection.close()

    with pytest.raises(ValueError, match="invalid hash chain"):
        SQLiteReplayLog(path)
