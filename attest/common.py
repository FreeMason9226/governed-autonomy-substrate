"""Shared helpers for signed PR attestations."""

from __future__ import annotations

import base64
import fcntl
import json
import math
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

REQUIRED_FIELDS = (
    "pr_id",
    "actor",
    "approver",
    "policy_id",
    "risk_score",
    "rationale",
    "timestamp",
    "commit_sha",
)


def canonicalize(payload: dict[str, Any]) -> bytes:
    """Serialize a JSON object deterministically for signing or verification."""
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def validate_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("attestation must be a JSON object")
    missing = [field for field in REQUIRED_FIELDS if field not in payload]
    if missing:
        raise ValueError(f"missing required field(s): {', '.join(missing)}")
    for field in ("actor", "approver", "policy_id", "rationale", "timestamp", "commit_sha"):
        if not isinstance(payload[field], str) or not payload[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    if isinstance(payload["pr_id"], bool) or not isinstance(payload["pr_id"], int):
        raise ValueError("pr_id must be an integer")
    risk_score = payload["risk_score"]
    if isinstance(risk_score, bool) or not isinstance(risk_score, (int, float)):
        raise ValueError("risk_score must be a number")
    if not math.isfinite(risk_score):
        raise ValueError("risk_score must be finite")
    return payload


def _sign(key: Any, message: bytes) -> bytes:
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise ValueError("RSA keys must be at least 2048 bits")
        return key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(message, ec.ECDSA(hashes.SHA256()))
    raise ValueError("private key must be RSA or ECDSA")


def sign_attestation(payload: dict[str, Any], private_key: Any) -> dict[str, Any]:
    validate_payload(payload)
    return {
        **payload,
        "signature": base64.b64encode(_sign(private_key, canonicalize(payload))).decode("ascii"),
    }


def _verify(key: Any, message: bytes, signature: bytes) -> bool:
    try:
        if isinstance(key, rsa.RSAPublicKey):
            if key.key_size < 2048:
                return False
            key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        else:
            return False
    except InvalidSignature:
        return False
    return True


def verify_attestation(attestation: Any, public_key: Any) -> bool:
    if not isinstance(attestation, dict) or "signature" not in attestation:
        raise ValueError("attestation signature is missing")
    signature_value = attestation["signature"]
    if not isinstance(signature_value, str):
        raise ValueError("signature must be a base64 string")
    payload = {key: value for key, value in attestation.items() if key != "signature"}
    validate_payload(payload)
    try:
        signature = base64.b64decode(signature_value, validate=True)
    except ValueError as exc:
        raise ValueError("signature is not valid base64") from exc
    return _verify(public_key, canonicalize(payload), signature)


def load_private_key(path: str | Path) -> Any:
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), None)


def load_public_key(path: str | Path) -> Any:
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def append_to_ledger(attestation_path: str | Path, ledger_path: str | Path) -> None:
    with open(attestation_path, encoding="utf-8") as attestation_file:
        attestation = json.load(attestation_file)
    line = json.dumps(attestation, separators=(",", ":"), sort_keys=True) + "\n"
    ledger = Path(ledger_path)
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.open("a", encoding="utf-8") as ledger_file:
        fcntl.flock(ledger_file.fileno(), fcntl.LOCK_EX)
        ledger_file.write(line)
        ledger_file.flush()
        fcntl.flock(ledger_file.fileno(), fcntl.LOCK_UN)
