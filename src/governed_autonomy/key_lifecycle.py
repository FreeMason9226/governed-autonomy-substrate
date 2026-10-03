"""Signing-key lifecycle (ACTIVE -> ROTATED -> REVOKED) bound to the TrustStore.

Rotated keys stay trusted so previously issued artifacts remain verifiable;
revoked keys are removed from trust immediately.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .trust import TrustStore

ACTIVE, ROTATED, REVOKED = "ACTIVE", "ROTATED", "REVOKED"


@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    provider: str
    status: str
    created_at: float
    revoked_at: float | None = None


class KeyLifecycleManager:
    def __init__(self, trust_store: TrustStore, path: str | Path = ":memory:") -> None:
        self.trust_store = trust_store
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS key_lifecycle (
                key_id TEXT PRIMARY KEY, provider TEXT NOT NULL, status TEXT NOT NULL,
                created_at REAL NOT NULL, revoked_at REAL)"""
        )
        self._db.commit()

    def register(self, key_id: str, provider: str, public_key: bytes) -> KeyRecord:
        if not key_id or not provider:
            raise ValueError("key_id and provider are required")
        with self._lock:
            if self._row(key_id) is not None:
                raise ValueError(f"key already registered: {key_id}")
            self.trust_store.add(key_id, Ed25519PublicKey.from_public_bytes(public_key))
            self._db.execute(
                "INSERT INTO key_lifecycle VALUES (?,?,?,?,NULL)",
                (key_id, provider, ACTIVE, time.time()),
            )
            self._db.commit()
            return self.get(key_id)

    def rotate(
        self, old_key_id: str, new_key_id: str, provider: str, new_public_key: bytes
    ) -> KeyRecord:
        with self._lock:
            old = self.get(old_key_id)
            if old.status != ACTIVE:
                raise ValueError("only an ACTIVE key can be rotated")
            new = self.register(new_key_id, provider, new_public_key)
            self._db.execute(
                "UPDATE key_lifecycle SET status=? WHERE key_id=?", (ROTATED, old_key_id)
            )
            self._db.commit()
            return new

    def revoke(self, key_id: str) -> KeyRecord:
        with self._lock:
            self.get(key_id)
            self.trust_store.revoke(key_id)
            self._db.execute(
                "UPDATE key_lifecycle SET status=?, revoked_at=? WHERE key_id=?",
                (REVOKED, time.time(), key_id),
            )
            self._db.commit()
            return self.get(key_id)

    def get(self, key_id: str) -> KeyRecord:
        row = self._row(key_id)
        if row is None:
            raise KeyError(f"unknown key: {key_id}")
        return KeyRecord(*row)

    def trust_list(self) -> list[KeyRecord]:
        rows = self._db.execute(
            "SELECT * FROM key_lifecycle WHERE status != ? ORDER BY created_at", (REVOKED,)
        ).fetchall()
        return [KeyRecord(*r) for r in rows]

    def active_key(self) -> KeyRecord | None:
        row = self._db.execute(
            "SELECT * FROM key_lifecycle WHERE status=? ORDER BY created_at DESC LIMIT 1",
            (ACTIVE,),
        ).fetchone()
        return KeyRecord(*row) if row else None

    def _row(self, key_id: str) -> tuple[str, str, str, float, float | None] | None:
        row = self._db.execute("SELECT * FROM key_lifecycle WHERE key_id=?", (key_id,)).fetchone()
        return (row[0], row[1], row[2], row[3], row[4]) if row else None
