"""Signer boundaries: private key material stays behind the signer interface."""

from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import b64encode


class Signer(Protocol):
    key_id: str

    def sign(self, payload: bytes) -> str: ...
    def public_key_bytes(self) -> bytes: ...


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


class KMSSigner:
    """Adapter for KMS/HSM-style signers that keep private material outside the process."""

    def __init__(
        self,
        key_id: str,
        kms_backend,
        *,
        public_key: bytes | None = None,
    ) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        if not hasattr(kms_backend, "sign") or not callable(kms_backend.sign):
            raise ValueError("kms_backend must implement .sign(key_id, payload)")
        self.key_id = key_id
        self._backend = kms_backend
        self._public_key = bytes(public_key) if public_key is not None else None

    def sign(self, payload: bytes) -> str:
        signature = self._backend.sign(self.key_id, bytes(payload))
        if not isinstance(signature, (bytes, bytearray)):
            raise TypeError("KMS signer backend must return raw signature bytes")
        return b64encode(bytes(signature))

    def public_key_bytes(self) -> bytes:
        if self._public_key is not None:
            return self._public_key
        public_key = getattr(self._backend, "public_key_bytes", None)
        if public_key is None or not callable(public_key):
            raise ValueError("KMS backend does not expose a public key for this signing key")
        return bytes(public_key(self.key_id))
