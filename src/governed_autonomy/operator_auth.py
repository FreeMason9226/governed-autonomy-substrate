"""SQLite-backed, hashed API credentials for administrative operators."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class OperatorAPIKey:
    key_id: str
    operator_id: str
    token_hash: str
    created_at: str
    revoked: bool = False

    def public_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "operator_id": self.operator_id,
            "created_at": self.created_at,
            "revoked": self.revoked,
        }


class OperatorKeyStore:
    """Durable operator credentials, storing token hashes and revocation state.

    The returned token is shown only on creation and cannot be recovered.
    SQLite transactions make key creation/revocation visible across server
    instances sharing this database path.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        try:
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS operator_api_keys (
                    key_id TEXT PRIMARY KEY,
                    operator_id TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
                )
                """
            )
        except sqlite3.Error:
            self._connection.close()
            raise

    def create(self, operator_id: str) -> dict[str, str]:
        if (
            not isinstance(operator_id, str)
            or not operator_id.strip()
            or len(operator_id.strip()) > 256
            or not operator_id.strip().isprintable()
        ):
            raise ValueError("operator_id must contain 1-256 printable characters")
        operator_id = operator_id.strip()
        key_id = uuid.uuid4().hex
        token = f"gasop_{key_id}.{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        created_at = datetime.now(UTC).isoformat()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT INTO operator_api_keys "
                    "(key_id, operator_id, token_hash, created_at) VALUES (?, ?, ?, ?)",
                    (key_id, operator_id, token_hash, created_at),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return {"key_id": key_id, "operator_id": operator_id, "token": token}

    def authenticate(self, token: str) -> OperatorAPIKey | None:
        if not isinstance(token, str) or not token.startswith("gasop_"):
            return None
        try:
            key_id, secret = token[6:].split(".", 1)
            token_bytes = token.encode("ascii")
        except (ValueError, UnicodeEncodeError):
            return None
        if not key_id or not secret:
            return None
        with self._lock:
            row = self._connection.execute(
                "SELECT operator_id, token_hash, created_at, revoked "
                "FROM operator_api_keys WHERE key_id = ?",
                (key_id,),
            ).fetchone()
        if row is None or row[3]:
            return None
        supplied_hash = hashlib.sha256(token_bytes).hexdigest()
        if not hmac.compare_digest(supplied_hash, row[1]):
            return None
        return OperatorAPIKey(key_id, row[0], row[1], row[2], bool(row[3]))

    def revoke(self, key_id: str) -> None:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT revoked FROM operator_api_keys WHERE key_id = ?", (key_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(f"unknown operator key: {key_id}")
                if row[0]:
                    raise ValueError(f"operator key is already revoked: {key_id}")
                self._connection.execute(
                    "UPDATE operator_api_keys SET revoked = 1 WHERE key_id = ?", (key_id,)
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise

    def list_keys(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT key_id, operator_id, created_at, revoked "
                "FROM operator_api_keys ORDER BY key_id"
            ).fetchall()
        return tuple(
            {
                "key_id": row[0],
                "operator_id": row[1],
                "created_at": row[2],
                "revoked": bool(row[3]),
            }
            for row in rows
        )

    def close(self) -> None:
        with self._lock:
            self._connection.close()
