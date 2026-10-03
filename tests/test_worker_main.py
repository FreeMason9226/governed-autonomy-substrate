from types import SimpleNamespace

import pytest

import tests.test_roadmap_platform as t
from governed_autonomy import (
    POSTGRES_JOBS_SCHEMA,
    PostgresJobStore,
)
from governed_autonomy.jobs import SQLiteJobStore
from governed_autonomy.worker import ContainerSandbox, WorkerRuntime
from governed_autonomy.worker_main import make_authorizer, serve


def test_serve_drains_queue_then_sleeps_until_stopped():
    service = t._service()
    store = SQLiteJobStore()
    ran = []
    for i in range(2):
        art = service.authorize(
            {"action": "run_job", "image": "alpine:3.20", "command": ["echo", str(i)]}, "jobs-v1"
        )
        store.enqueue({"artifact": art.to_json()}, idempotency_key=f"k{i}", max_attempts=1)

    def runner(argv, **kw):
        ran.append(argv[-1])
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    worker = WorkerRuntime(
        store,
        authorizer=make_authorizer(service),
        secrets=t.StaticSecrets(),
        sandbox=ContainerSandbox(["alpine:3.20"], runner=runner),
        retry_delay=0,
    )
    sleeps = []
    assert serve(worker, poll_seconds=1, should_stop=lambda: bool(sleeps), sleep=sleeps.append) == 2
    assert ran == ["0", "1"] and sleeps == [1]


def test_authorizer_rejects_missing_artifact():
    with pytest.raises(ValueError):
        make_authorizer(t._service())({"image": "x"})


class FakeCursor:
    def __init__(self, log):
        self.log = log

    def execute(self, sql, params=()):
        self.log.append((sql, params))

    def fetchone(self):
        return ("id", "key", "{}", "running", 1, 3, 0.0, None)

    def fetchall(self):
        return []

    def close(self):
        pass


class FakeConn:
    def __init__(self):
        self.log = []
        self.commits = 0

    def cursor(self):
        return FakeCursor(self.log)

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass


def test_postgres_job_store_claim_uses_skip_locked_and_lease_reclaim():
    conn = FakeConn()
    store = PostgresJobStore(conn, lease_seconds=60)
    assert POSTGRES_JOBS_SCHEMA in conn.log[0][0]
    job = store.claim(now=100.0)
    sql, params = conn.log[-1]
    assert "SKIP LOCKED" in sql and "lease_expires_at<=" in sql
    assert params == (160.0, 100.0, 100.0) and job.status == "running"
    with pytest.raises(ValueError):
        PostgresJobStore(conn, lease_seconds=0)


def test_worker_metrics_count_outcomes_and_serve_prometheus():
    import urllib.request

    from governed_autonomy.worker_main import start_metrics_server

    service = t._service()
    store = SQLiteJobStore()
    good = service.authorize(
        {"action": "run_job", "image": "alpine:3.20", "command": ["true"]}, "jobs-v1"
    )
    store.enqueue({"artifact": good.to_json()}, idempotency_key="g", max_attempts=1)
    store.enqueue({"image": "x"}, idempotency_key="bad", max_attempts=1)
    worker = WorkerRuntime(
        store,
        authorizer=make_authorizer(service),
        secrets=t.StaticSecrets(),
        sandbox=ContainerSandbox(
            ["alpine:3.20"],
            runner=lambda *a, **k: SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
        ),
        retry_delay=0,
    )
    while worker.process_once():
        pass
    server = start_metrics_server(worker.metrics, 0)
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/metrics"
        body = urllib.request.urlopen(url, timeout=5).read().decode()
    finally:
        server.shutdown()
        server.server_close()
    assert "governed_autonomy_worker_jobs_processed_total 2" in body
    assert "governed_autonomy_worker_jobs_succeeded_total 1" in body
    assert "governed_autonomy_worker_jobs_dead_lettered_total 1" in body
    assert "governed_autonomy_worker_jobs_denied_total 1" in body
