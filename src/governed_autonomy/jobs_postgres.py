"""PostgreSQL job store safe for many concurrent worker replicas.

Claims use ``FOR UPDATE SKIP LOCKED`` so replicas never receive the same job, and
jobs left ``running`` by a crashed worker are reclaimed once their lease expires.
The ``connection`` is a psycopg 3 connection (injected, like ``PostgresReplayLog``).
"""

from __future__ import annotations

import json
import threading
import uuid
from typing import Any

from .jobs import Job, JobStoreError

POSTGRES_JOBS_SCHEMA = """CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL,
    status TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL,
    available_at DOUBLE PRECISION NOT NULL,
    last_error TEXT,
    lease_expires_at DOUBLE PRECISION
);
CREATE INDEX IF NOT EXISTS jobs_claim_idx ON jobs (status, available_at);"""

_COLUMNS = (
    "job_id, idempotency_key, payload::text, status, attempts, max_attempts, "
    "available_at, last_error"
)


class PostgresJobStore:
    def __init__(self, connection: Any, *, lease_seconds: float = 300.0) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.connection, self.lease_seconds = connection, lease_seconds
        self._lock = threading.RLock()
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute(POSTGRES_JOBS_SCHEMA)
                self.connection.commit()
            finally:
                cursor.close()

    def _run(self, sql: str, params: tuple[Any, ...] = (), *, fetch: str | None = None) -> Any:
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute(sql, params)
                result = (
                    cursor.fetchone() if fetch == "one" else cursor.fetchall() if fetch else None
                )
                self.connection.commit()
                return result
            except Exception as exc:
                self.connection.rollback()
                raise JobStoreError("PostgreSQL job store operation failed") from exc
            finally:
                cursor.close()

    def enqueue(
        self,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
        max_attempts: int = 3,
        delay_seconds: float = 0,
        now: float | None = None,
    ) -> Job:
        if not idempotency_key or max_attempts <= 0:
            raise ValueError("idempotency_key and positive max_attempts are required")
        import time

        job_id = uuid.uuid4().hex
        self._run(
            "INSERT INTO jobs (job_id, idempotency_key, payload, status, attempts, max_attempts,"
            " available_at) VALUES (%s, %s, %s::jsonb, 'queued', 0, %s, %s)"
            " ON CONFLICT (idempotency_key) DO NOTHING",
            (
                job_id,
                idempotency_key,
                json.dumps(payload, sort_keys=True),
                max_attempts,
                (time.time() if now is None else now) + delay_seconds,
            ),
        )
        row = self._run(
            f"SELECT {_COLUMNS} FROM jobs WHERE idempotency_key=%s", (idempotency_key,), fetch="one"
        )
        return self._job(row)

    def get(self, job_id: str) -> Job:
        row = self._run(f"SELECT {_COLUMNS} FROM jobs WHERE job_id=%s", (job_id,), fetch="one")
        if row is None:
            raise KeyError("unknown job")
        return self._job(row)

    def claim(self, now: float | None = None) -> Job | None:
        import time

        moment = time.time() if now is None else now
        row = self._run(
            "UPDATE jobs SET status='running', attempts=attempts+1, lease_expires_at=%s"
            " WHERE job_id = (SELECT job_id FROM jobs"
            "   WHERE (status='queued' AND available_at<=%s)"
            "      OR (status='running' AND lease_expires_at<=%s)"
            "   ORDER BY available_at, job_id LIMIT 1 FOR UPDATE SKIP LOCKED)"
            f" RETURNING {_COLUMNS}",
            (moment + self.lease_seconds, moment, moment),
            fetch="one",
        )
        return self._job(row) if row else None

    def complete(self, job_id: str) -> None:
        self._run(
            "UPDATE jobs SET status='succeeded', lease_expires_at=NULL"
            " WHERE job_id=%s AND status='running'",
            (job_id,),
        )

    def fail(self, job_id: str, error: str, *, retry_delay: float = 1.0) -> None:
        import time

        self._run(
            "UPDATE jobs SET status=CASE WHEN attempts < max_attempts THEN 'queued'"
            " ELSE 'dead_letter' END, last_error=%s, available_at=%s, lease_expires_at=NULL"
            " WHERE job_id=%s",
            (error[:512], time.time() + retry_delay, job_id),
        )

    @staticmethod
    def _job(row: tuple[Any, ...]) -> Job:
        payload = json.loads(row[2]) if isinstance(row[2], str) else row[2]
        return Job(row[0], row[1], payload, row[3], row[4], row[5], row[6], row[7])
