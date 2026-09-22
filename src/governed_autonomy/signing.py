"""Signer boundaries: private key material stays behind the signer interface."""
from __future__ import annotations

from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64encode


class Signer(Protocol):
    key_id: str
    def sign(self, payload: bytes) -> str: ...
    def public_key_bytes(self) -> bytes: ...


class LocalEd25519Signer:
    def __init__(self, key_id: str = "local-signer", private_key: Ed25519PrivateKey | None = None) -> None:
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
