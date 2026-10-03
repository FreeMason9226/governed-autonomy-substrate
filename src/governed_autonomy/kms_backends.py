"""Concrete KMS backends for :class:`governed_autonomy.signing.KMSSigner`.

Private key material never enters this process: only ``Sign`` and
``GetPublicKey`` calls are made. The signing algorithm is Ed25519 so signatures
verify against the existing trust store and wire format.
"""

from __future__ import annotations

from importlib import import_module
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

AWS_ED25519_ALGORITHM = "ED25519_SHA_512"


class KMSBackendError(RuntimeError):
    """Raised when the KMS provider fails or returns an unusable response."""


class AwsKmsBackend:
    """AWS KMS backend using an ``ECC_NIST_EDWARDS25519`` key (RAW Ed25519 signing).

    ``client`` may be injected (tests, custom credentials/endpoints); otherwise
    ``boto3`` is imported lazily so it stays an optional dependency.
    """

    def __init__(self, client: Any | None = None, *, region_name: str | None = None) -> None:
        if client is None:
            try:
                boto3 = import_module("boto3")
            except ImportError as exc:
                raise KMSBackendError("boto3 is required: pip install .[aws]") from exc
            client = boto3.client("kms", region_name=region_name)
        self._client = client

    def sign(self, key_id: str, payload: bytes) -> bytes:
        try:
            response = self._client.sign(
                KeyId=key_id,
                Message=bytes(payload),
                MessageType="RAW",
                SigningAlgorithm=AWS_ED25519_ALGORITHM,
            )
        except Exception as exc:
            raise KMSBackendError(f"KMS sign failed: {type(exc).__name__}") from exc
        signature = response.get("Signature") if isinstance(response, dict) else None
        if not isinstance(signature, (bytes, bytearray)):
            raise KMSBackendError("KMS sign returned no signature")
        return bytes(signature)

    def public_key_bytes(self, key_id: str) -> bytes:
        try:
            response = self._client.get_public_key(KeyId=key_id)
        except Exception as exc:
            raise KMSBackendError(f"KMS get_public_key failed: {type(exc).__name__}") from exc
        der = response.get("PublicKey") if isinstance(response, dict) else None
        if not isinstance(der, (bytes, bytearray)):
            raise KMSBackendError("KMS get_public_key returned no key")
        key = load_der_public_key(bytes(der))
        if not isinstance(key, Ed25519PublicKey):
            raise KMSBackendError("KMS key is not Ed25519")
        return key.public_bytes(Encoding.Raw, PublicFormat.Raw)
