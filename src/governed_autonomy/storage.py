"""Small repository boundaries for distributed nonce coordination."""

from __future__ import annotations

import json
import sqlite3
import threading
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64decode, b64encode
from .replay import ReplayFrame, ReplayLog
from .trust import TrustStore


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

POSTGRES_TRUST_SCHEMA = """CREATE TABLE IF NOT EXISTS trust_keys (
    key_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);"""


class PostgresTrustStore(TrustStore):
    """PostgreSQL-backed issuer trust and revocation registry."""

    def __init__(self, connection) -> None:
        self.connection = connection
        self._lock = threading.RLock()
        cursor = self.connection.cursor()
        try:
            cursor.execute(POSTGRES_TRUST_SCHEMA)
            self.connection.commit()
        finally:
            cursor.close()

    def add(self, key_id: str, public_key: Ed25519PublicKey) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("SELECT revoked FROM trust_keys WHERE key_id=%s", (key_id,))
                row = cursor.fetchone()
                if row is not None and not row[0]:
                    raise ValueError(f"issuer key already exists: {key_id}")
                cursor.execute(
                    "INSERT INTO trust_keys(key_id, public_key, revoked) VALUES (%s,%s,FALSE) "
                    "ON CONFLICT (key_id) DO UPDATE SET public_key=EXCLUDED.public_key, "
                    "revoked=FALSE, updated_at=CURRENT_TIMESTAMP",
                    (key_id, b64encode(public_key.public_bytes_raw())),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            finally:
                cursor.close()

    def revoke(self, key_id: str) -> None:
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute(
                    "UPDATE trust_keys SET revoked=TRUE, updated_at=CURRENT_TIMESTAMP "
                    "WHERE key_id=%s",
                    (key_id,),
                )
                if cursor.rowcount != 1:
                    raise KeyError(f"unknown issuer key: {key_id}")
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            finally:
                cursor.close()

    def resolve(self, key_id: str) -> Ed25519PublicKey | None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT public_key, revoked FROM trust_keys WHERE key_id=%s", (key_id,)
            )
            row = cursor.fetchone()
            if row is None or row[1]:
                return None
            return Ed25519PublicKey.from_public_bytes(b64decode(row[0]))
        finally:
            cursor.close()

    def to_dict(self) -> dict[str, object]:
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT key_id, public_key, revoked FROM trust_keys ORDER BY key_id")
            rows = cursor.fetchall()
        finally:
            cursor.close()
        return {
            "keys": {row[0]: row[1] for row in rows},
            "revoked": [row[0] for row in rows if row[2]],
        }


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

    def _refresh(self, cursor) -> None:
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

    def get(self, frame_id: str) -> ReplayFrame | None:
        with self._lock:
            cursor = self.connection.cursor()
            try:
                self._refresh(cursor)
                return super().get(frame_id)
            finally:
                cursor.close()

    def nonce_used(self, nonce: str) -> bool:
        with self._lock:
            cursor = self.connection.cursor()
            try:
                self._refresh(cursor)
                return super().nonce_used(nonce)
            finally:
                cursor.close()

    def audit_summary(self) -> dict[str, object]:
        with self._lock:
            cursor = self.connection.cursor()
            try:
                self._refresh(cursor)
                return super().audit_summary()
            finally:
                cursor.close()

    def verify_chain(self) -> bool:
        return super().verify_chain()

    def append(
        self,
        frame_id: str,
        event: dict[str, object],
    ) -> ReplayFrame:
        with self._lock:
            cursor = self.connection.cursor()
            try:
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext('gas.replay.append'))")
                self._refresh(cursor)
            finally:
                cursor.close()
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
                cursor.execute("SELECT pg_advisory_xact_lock(hashtext('gas.nonce.claim'))")
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
