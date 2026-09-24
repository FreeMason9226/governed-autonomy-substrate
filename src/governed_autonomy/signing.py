"""Signer boundaries: private key material stays behind the signer interface."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import time
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import b64encode


class Signer(Protocol):
    key_id: str

    def sign(self, payload: bytes) -> str: ...
    def public_key_bytes(self) -> bytes: ...


@dataclass(frozen=True)
class KeyOperation:
    operation: str
    key_id: str
    recorded_at: int
    details: Mapping[str, Any]


class ImmutableKeyAuditLog:
    """Append-only in-process audit view; production deployments persist each record externally."""

    def __init__(self) -> None:
        self._entries: list[KeyOperation] = []

    def append(self, operation: str, key_id: str, details: dict[str, Any] | None = None) -> None:
        self._entries.append(
            KeyOperation(operation, key_id, int(time.time()), MappingProxyType(dict(details or {})))
        )

    @property
    def entries(self) -> tuple[KeyOperation, ...]:
        return tuple(self._entries)


class LocalEd25519Signer:
    def __init__(
        self, key_id: str = "local-signer", private_key: Ed25519PrivateKey | None = None
    ) -> None:
        self.key_id = key_id
        self._private_key = private_key or Ed25519PrivateKey.generate()

    def sign(self, payload: bytes) -> str:
        return b64encode(self._private_key.sign(payload))

    def public_key_bytes(self) -> bytes:
        return self._private_key.public_key().public_bytes_raw()


class RemoteSigner:
    """Provider boundary. The callback receives bytes only; no private key is accepted."""

    def __init__(self, key_id: str, sign_callback, public_key: bytes) -> None:
        if not key_id or not callable(sign_callback) or not public_key:
            raise ValueError("key_id, callback, and public_key are required")
        self.key_id, self._callback, self._public_key = key_id, sign_callback, bytes(public_key)

    def sign(self, payload: bytes) -> str:
        signature = self._callback(bytes(payload))
        if not isinstance(signature, bytes):
            raise TypeError("remote signer must return signature bytes")
        return b64encode(signature)

    def public_key_bytes(self) -> bytes:
        return self._public_key


class KMSHSMBackedSigner(RemoteSigner):
    """KMS/HSM provider boundary; private key material is never accepted."""

    def __init__(
        self,
        key_id: str,
        sign_callback: Callable[[bytes], bytes],
        public_key: bytes,
        *,
        audit_hook: Callable[[str, dict[str, Any]], None] | None = None,
        audit_log: ImmutableKeyAuditLog | None = None,
    ) -> None:
        super().__init__(key_id, sign_callback, public_key)
        self._audit_hook = audit_hook
        self._audit_log = audit_log

    def _record(self, operation: str, details: dict[str, Any]) -> None:
        if self._audit_log is not None:
            self._audit_log.append(operation, self.key_id, details)
        if self._audit_hook is not None:
            self._audit_hook(operation, details)

    def sign(self, payload: bytes) -> str:
        signature = super().sign(payload)
        self._record("kms.sign", {"key_id": self.key_id, "payload_bytes": len(payload)})
        return signature

    def rotate(self, *, public_key: bytes, key_id: str) -> None:
        if not key_id or not public_key:
            raise ValueError("key_id and public_key are required")
        old_key_id = self.key_id
        self.key_id = key_id
        self._public_key = bytes(public_key)
        self._record("kms.rotate", {"old_key_id": old_key_id, "new_key_id": key_id})

    def rotate_if_due(
        self,
        *,
        now: int,
        last_rotated_at: int,
        interval_seconds: int,
        fetch_next_key: Callable[[], tuple[str, bytes]],
    ) -> bool:
        if interval_seconds <= 0:
            raise ValueError("rotation interval must be positive")
        if now - last_rotated_at < interval_seconds:
            return False
        next_key_id, next_public_key = fetch_next_key()
        self.rotate(public_key=next_public_key, key_id=next_key_id)
        return True
