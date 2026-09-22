"""Small repository boundaries for distributed nonce coordination."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Protocol

from .replay import ReplayFrame, ReplayLog


class NonceRepository(Protocol):
    def claim(self, nonce: str) -> None: ...
    def contains(self, nonce: str) -> bool: ...


class SQLiteNonceRepository:
    def __init__(self, path: str = ":memory:") -> None:
        self.connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute(
            "CREATE TABLE IF NOT EXISTS consumed_nonces (nonce TEXT PRIMARY KEY)"
        )
        self._lock = threading.RLock()

    def claim(self, nonce: str) -> None:
        if not nonce:
            raise ValueError("nonce must not be empty")
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("INSERT INTO consumed_nonces(nonce) VALUES (?)", (nonce,))
                self.connection.commit()
            except sqlite3.IntegrityError as exc:
                self.connection.rollback()
                raise ValueError(f"nonce already consumed: {nonce}") from exc

    def contains(self, nonce: str) -> bool:
        return (
            self.connection.execute(
                "SELECT 1 FROM consumed_nonces WHERE nonce=?", (nonce,)
            ).fetchone()
            is not None
        )

    def close(self) -> None:
        self.connection.close()


POSTGRES_NONCE_SCHEMA = """CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce TEXT PRIMARY KEY,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);"""

POSTGRES_REPLAY_SCHEMA = """CREATE TABLE IF NOT EXISTS replay_frames (
    sequence BIGSERIAL PRIMARY KEY,
    frame_id TEXT UNIQUE NOT NULL,
    nonce TEXT,
    frame_json JSONB NOT NULL,
    frame_hash TEXT NOT NULL,
    previous_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);"""


class PostgresReplayLog(ReplayLog):
    """PostgreSQL-backed replay log with transactional append and nonce claims."""

    def __init__(self, connection) -> None:
        self.connection = connection
        self._lock = threading.RLock()
        self._frames: list[ReplayFrame] = []
        self._used_nonces: set[str] = set()
        cursor = self.connection.cursor()
        try:
            cursor.execute(POSTGRES_NONCE_SCHEMA)
            cursor.execute(POSTGRES_REPLAY_SCHEMA)
            self.connection.commit()
            cursor.execute(
                "SELECT frame_id, previous_hash, frame_json::text, frame_hash "
                "FROM replay_frames ORDER BY sequence"
            )
            self._frames = [
                ReplayFrame(row[0], row[1] or "", json.loads(row[2]), row[3])
                for row in cursor.fetchall()
            ]
            cursor.execute("SELECT nonce FROM consumed_nonces")
            self._used_nonces = {row[0] for row in cursor.fetchall()}
        finally:
            cursor.close()
        if not self.verify_chain():
            raise ValueError("PostgreSQL replay log contains an invalid hash chain")

    def append(
        self,
        frame_id: str,
        event: dict[str, object],
    ) -> ReplayFrame:
        with self._lock:
            frame = ReplayFrame.create(
                frame_id,
                self._frames[-1].frame_hash if self._frames else "",
                event,
            )
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    "INSERT INTO replay_frames(frame_id,nonce,frame_json,frame_hash,previous_hash) "
                    "VALUES (%s,%s,%s::jsonb,%s,%s)",
                    (
                        frame.frame_id,
                        event.get("nonce"),
                        json.dumps(event, sort_keys=True, separators=(",", ":")),
                        frame.frame_hash,
                        frame.previous_hash,
                    ),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            finally:
                cursor.close()
            self._frames.append(frame)
            return frame

    def claim_nonce(self, nonce: str) -> None:
        if not nonce:
            raise ValueError("nonce must not be empty")
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("INSERT INTO consumed_nonces (nonce) VALUES (%s)", (nonce,))
                self.connection.commit()
            except Exception as exc:
                self.connection.rollback()
                raise ValueError(f"nonce already consumed: {nonce}") from exc
            finally:
                cursor.close()
            self._used_nonces.add(nonce)

    def close(self) -> None:
        self.connection.close()


class PostgresNonceRepository:
    """Adapter boundary for psycopg/asyncpg-like connections; dependency stays optional."""

    def __init__(self, connection) -> None:
        self.connection = connection

    def claim(self, nonce: str) -> None:
        if not nonce:
            raise ValueError("nonce must not be empty")
        cursor = self.connection.cursor()
        try:
            cursor.execute("INSERT INTO consumed_nonces (nonce) VALUES (%s)", (nonce,))
            self.connection.commit()
        except Exception as exc:
            self.connection.rollback()
            raise ValueError("nonce already consumed or database unavailable") from exc
        finally:
            cursor.close()

    def contains(self, nonce: str) -> bool:
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT 1 FROM consumed_nonces WHERE nonce=%s", (nonce,))
            return cursor.fetchone() is not None
        finally:
            cursor.close()
