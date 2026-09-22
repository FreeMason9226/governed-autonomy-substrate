"""Small repository boundaries for distributed nonce coordination."""
from __future__ import annotations

import sqlite3
import threading
from typing import Protocol


class NonceRepository(Protocol):
    def claim(self, nonce: str) -> None: ...
    def contains(self, nonce: str) -> bool: ...


class SQLiteNonceRepository:
    def __init__(self, path: str = ":memory:") -> None:
        self.connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.connection.execute("CREATE TABLE IF NOT EXISTS consumed_nonces (nonce TEXT PRIMARY KEY)")
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
        return self.connection.execute("SELECT 1 FROM consumed_nonces WHERE nonce=?", (nonce,)).fetchone() is not None

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


class PostgresReplayLog:
    """Small DB-API boundary; deployments own pooling, TLS, and migrations."""
    def __init__(self, connection) -> None:
        self.connection = connection

    def append(self, frame_id: str, frame_json: str, frame_hash: str, previous_hash: str | None = None,
               nonce: str | None = None) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO replay_frames(frame_id,nonce,frame_json,frame_hash,previous_hash) VALUES (%s,%s,%s::jsonb,%s,%s)",
                (frame_id, nonce, frame_json, frame_hash, previous_hash),
            )
            self.connection.commit()
        finally:
            cursor.close()


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
