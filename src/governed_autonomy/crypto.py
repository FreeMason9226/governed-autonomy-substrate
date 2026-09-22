from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import b64decode, b64encode


@dataclass(frozen=True)
class KeyPair:
    """Ed25519 issuer key pair; private material is never serialized by the MVP."""

    private_key: Ed25519PrivateKey
    key_id: str

    @classmethod
    def generate(cls, key_id: str = "issuer-1") -> "KeyPair":
        return cls(Ed25519PrivateKey.generate(), key_id)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes_raw()

    def sign(self, payload: bytes) -> str:
        return b64encode(self.private_key.sign(payload))


def verify_signature(public_key: Ed25519PublicKey, payload: bytes, signature: str) -> bool:
    try:
        public_key.verify(b64decode(signature), payload)
    except (InvalidSignature, ValueError):
        return False
    return True
