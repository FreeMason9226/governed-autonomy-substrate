import json
import os
import threading
import uuid
from http.client import HTTPConnection
from types import SimpleNamespace

import pytest

from governed_autonomy import PostgresJobStore, build_demo_service, create_server
from governed_autonomy.jobs import run_once
from governed_autonomy.worker import ContainerSandbox, WorkerRuntime


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


def test_admin_api_submits_to_and_reads_from_postgres_queue(connection):
    psycopg = pytest.importorskip("psycopg")
    schema = "gas_test_" + uuid.uuid4().hex
    cursor = connection.cursor()
    cursor.execute(f'CREATE SCHEMA "{schema}"')
    connection.commit()
    cursor.close()
    worker_connection = psycopg.connect(
        os.environ["GAS_POSTGRES_TEST_URL"], options=f"-c search_path={schema}"
    )
    store = PostgresJobStore(worker_connection)
    service, _, _ = build_demo_service()
    service.actions["write_file"] = lambda _: {
        "image": "alpine:3.20",
        "command": ["echo", "api-to-worker"],
    }
    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "signed request"},
        "demo-files-v1",
    )
    sandbox_calls = []

    def runner(argv, **kwargs):
        sandbox_calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout=b"ok", stderr=b"")

    server = create_server(
        service,
        bearer_token="test-token",
        operator_token="test-token",
        job_store=store,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = HTTPConnection(*server.server_address)
        body = json.dumps(
            {
                "artifact": artifact.to_dict(),
                "idempotency_key": _key(),
                "image": "untrusted:latest",
                "command": ["rm", "-rf", "/"],
            }
        ).encode()
        client.request(
            "POST",
            "/admin/jobs",
            body=body,
            headers={
                "Authorization": "Bearer test-token",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        response = client.getresponse()
        submitted = json.loads(response.read())
        assert response.status == 202

        client.request(
            "GET",
            f"/admin/jobs/{submitted['job_id']}",
            headers={"Authorization": "Bearer test-token"},
        )
        response = client.getresponse()
        status = json.loads(response.read())
        assert response.status == 200
        assert status["job_id"] == submitted["job_id"]
        assert status["status"] == "queued"

        class NoSecrets:
            def fetch(self, policy_id, required_keys):
                return {}

        worker = WorkerRuntime(
            store,
            authorizer=lambda payload: service.execute_json(payload["artifact"]),
            secrets=NoSecrets(),
            sandbox=ContainerSandbox(["alpine:3.20"], runner=runner),
            retry_delay=0,
        )
        completed = worker.process_once()
        assert completed is not None and completed.status == "succeeded"
        assert sandbox_calls[0][0][-2:] == ["echo", "api-to-worker"]
        assert "untrusted:latest" not in sandbox_calls[0][0]
        assert worker.metrics.counts["succeeded"] == 1

        client.request(
            "GET",
            f"/admin/jobs/{submitted['job_id']}",
            headers={"Authorization": "Bearer test-token"},
        )
        response = client.getresponse()
        status = json.loads(response.read())
        assert response.status == 200 and status["status"] == "succeeded"
        assert status["attempts"] == 1
        client.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        worker_connection.close()
        cursor = connection.cursor()
        cursor.execute(f'DROP SCHEMA "{schema}" CASCADE')
        connection.commit()
        cursor.close()
