import os
import threading
import uuid

import pytest

from governed_autonomy import PostgresJobStore
from governed_autonomy.jobs import run_once


@pytest.fixture
def connection():
    url = os.environ.get("GAS_POSTGRES_TEST_URL")
    if not url:
        pytest.skip("GAS_POSTGRES_TEST_URL is not configured")
    psycopg = pytest.importorskip("psycopg")
    conn = psycopg.connect(url)
    yield conn
    conn.close()


def _key() -> str:
    return "t-" + uuid.uuid4().hex


def test_enqueue_is_idempotent_and_retries_then_dead_letters(connection):
    store = PostgresJobStore(connection)
    key = _key()
    first = store.enqueue({"a": 1}, idempotency_key=key, max_attempts=2)
    assert store.enqueue({"a": 2}, idempotency_key=key).job_id == first.job_id
    assert store.get(first.job_id).payload == {"a": 1}

    def boom(_):
        raise RuntimeError("no")

    # drain any unrelated queued rows so we only observe our own job
    seen = set()
    for _ in range(50):
        job = run_once(store, boom, retry_delay=0)
        if job is None:
            break
        seen.add(job.job_id)
        if store.get(first.job_id).status == "dead_letter":
            break
    final = store.get(first.job_id)
    assert final.status == "dead_letter" and final.attempts == 2


def test_concurrent_claims_never_return_the_same_job(connection):
    psycopg = pytest.importorskip("psycopg")
    url = os.environ["GAS_POSTGRES_TEST_URL"]
    setup = PostgresJobStore(connection)
    tag = _key()
    ids = {setup.enqueue({"n": i}, idempotency_key=f"{tag}-{i}").job_id for i in range(8)}
    claimed: list[str] = []
    lock = threading.Lock()

    def worker() -> None:
        with psycopg.connect(url) as conn:
            store = PostgresJobStore(conn)
            while (job := store.claim()) is not None:
                with lock:
                    claimed.append(job.job_id)
                store.complete(job.job_id)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ours = [c for c in claimed if c in ids]
    assert sorted(ours) == sorted(ids) and len(set(claimed)) == len(claimed)


def test_expired_lease_is_reclaimed(connection):
    store = PostgresJobStore(connection, lease_seconds=10)
    job = store.enqueue({"x": 1}, idempotency_key=_key(), now=0.0)
    cur = connection.cursor()
    cur.execute("UPDATE jobs SET available_at=-1e9 WHERE job_id=%s", (job.job_id,))
    connection.commit()
    cur.close()
    first = store.claim(now=1.0)
    assert first is not None and first.job_id == job.job_id
    assert store.claim(now=5.0) is None
    again = store.claim(now=20.0)
    assert again is not None and again.job_id == job.job_id and again.attempts == 2
