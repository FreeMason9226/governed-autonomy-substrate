"""Durable, provider-neutral asynchronous job state.

Execution remains behind the governance barrier; this module only persists
delivery state and provides bounded retry/dead-letter semantics.
"""
from __future__ import annotations

import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Job:
    job_id: str
    idempotency_key: str
    payload: dict[str, Any]
    status: str
    attempts: int
    max_attempts: int
    available_at: float
    last_error: str | None = None


class SQLiteJobStore:
    def __init__(self, path: str = ":memory:") -> None:
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("""CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE, payload TEXT NOT NULL,
            status TEXT NOT NULL, attempts INTEGER NOT NULL, max_attempts INTEGER NOT NULL,
            available_at REAL NOT NULL, last_error TEXT)""")
        self.db.commit()

    def enqueue(self, payload: dict[str, Any], *, idempotency_key: str,
                max_attempts: int = 3, delay_seconds: float = 0) -> Job:
        if not idempotency_key or max_attempts <= 0:
            raise ValueError("idempotency_key and positive max_attempts are required")
        import json
        existing = self.db.execute("SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
        if existing:
            return self._row(existing)
        job_id = uuid.uuid4().hex
        self.db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?)",
                        (job_id, idempotency_key, json.dumps(payload, sort_keys=True),
                         "queued", 0, max_attempts, time.time() + delay_seconds, None))
        self.db.commit()
        return self.get(job_id)

    def get(self, job_id: str) -> Job:
        row = self.db.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError("unknown job")
        return self._row(row)

    def claim(self) -> Job | None:
        row = self.db.execute("""SELECT * FROM jobs WHERE status='queued' AND available_at<=?
                                 ORDER BY available_at, job_id LIMIT 1""", (time.time(),)).fetchone()
        if row is None:
            return None
        self.db.execute("UPDATE jobs SET status='running', attempts=attempts+1 WHERE job_id=? AND status='queued'", (row[0],))
        self.db.commit()
        return self.get(row[0])

    def complete(self, job_id: str) -> None:
        self.db.execute("UPDATE jobs SET status='succeeded' WHERE job_id=? AND status='running'", (job_id,))
        self.db.commit()

    def fail(self, job_id: str, error: str, *, retry_delay: float = 1.0) -> None:
        job = self.get(job_id)
        status = "queued" if job.attempts < job.max_attempts else "dead_letter"
        self.db.execute("UPDATE jobs SET status=?, last_error=?, available_at=? WHERE job_id=?",
                        (status, error[:512], time.time() + retry_delay, job_id))
        self.db.commit()

    def _row(self, row: tuple[Any, ...]) -> Job:
        import json
        return Job(row[0], row[1], json.loads(row[2]), row[3], row[4], row[5], row[6], row[7])


def run_once(store: SQLiteJobStore, handler: Callable[[dict[str, Any]], None],
             compensation: Callable[[Job, Exception], None] | None = None,
             retry_delay: float = 1.0) -> Job | None:
    job = store.claim()
    if job is None:
        return None
    try:
        handler(job.payload)
    except (ValueError, RuntimeError, TimeoutError, OSError) as exc:
        store.fail(job.job_id, type(exc).__name__, retry_delay=retry_delay)
        if store.get(job.job_id).status == "dead_letter" and compensation is not None:
            compensation(job, exc)
    else:
        store.complete(job.job_id)
    return store.get(job.job_id)
