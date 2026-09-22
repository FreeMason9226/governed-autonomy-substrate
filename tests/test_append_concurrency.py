from concurrent.futures import ThreadPoolExecutor

from governed_autonomy import ReplayLog, SQLiteReplayLog


def test_memory_append_serializes_hash_chain():
    log = ReplayLog()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda index: log.append(
                    f"frame-{index}", {"type": "audit", "index": index}
                ),
                range(100),
            )
        )

    assert len(log.frames) == 100
    assert log.verify_chain()


def test_sqlite_append_serializes_hash_chain(tmp_path):
    log = SQLiteReplayLog(tmp_path / "replay.db")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda index: log.append(
                    f"frame-{index}", {"type": "audit", "index": index}
                ),
                range(100),
            )
        )

    assert len(log.frames) == 100
    assert log.verify_chain()
    log.close()
