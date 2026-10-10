import base64
import json
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from attest.common import canonicalize, sign_attestation, verify_attestation
from attest.generate_attestation import build_attestation


def sample_payload():
    return {
        "pr_id": 123,
        "actor": "ai-bot",
        "approver": "alice@example.com",
        "policy_id": "policy-001",
        "risk_score": 8,
        "rationale": "Policy checks passed",
        "timestamp": "2026-10-07T23:00:00+00:00",
        "commit_sha": "abcdef123",
    }


@pytest.mark.parametrize(
    "private_key",
    [rsa.generate_private_key(public_exponent=65537, key_size=2048),
     ec.generate_private_key(ec.SECP256R1())],
)
def test_generation_and_signature_verification(private_key):
    attestation = sign_attestation(sample_payload(), private_key)

    assert set(attestation) == {*sample_payload(), "signature"}
    assert isinstance(attestation["signature"], str)
    assert verify_attestation(attestation, private_key.public_key())


def test_generator_builds_required_pr_metadata():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attestation = build_attestation(
        123, "ai-bot", "alice@example.com", "policy-001", 8, "Passed",
        "abcdef123", key, timestamp="2026-10-07T23:00:00Z",
    )

    assert attestation["pr_id"] == 123
    assert attestation["timestamp"] == "2026-10-07T23:00:00Z"
    assert verify_attestation(attestation, key.public_key())


def test_invalid_signature_fails():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attestation = sign_attestation(sample_payload(), key)
    attestation["signature"] = base64.b64encode(b"not a valid signature").decode("ascii")

    assert not verify_attestation(attestation, key.public_key())


def test_modified_payload_fails_verification():
    key = ec.generate_private_key(ec.SECP256R1())
    attestation = sign_attestation(sample_payload(), key)
    attestation["approver"] = "mallory@example.com"

    assert not verify_attestation(attestation, key.public_key())


def test_missing_required_fields_are_reported():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attestation = sign_attestation(sample_payload(), key)
    del attestation["rationale"]

    with pytest.raises(ValueError, match="rationale"):
        verify_attestation(attestation, key.public_key())


def test_canonicalization_is_sorted_compact_json():
    assert canonicalize({"z": 1, "a": {"y": 2, "b": 3}}) == b'{"a":{"b":3,"y":2},"z":1}'
    assert canonicalize(json.loads('{"z": 1, "a": 2}')) == b'{"a":2,"z":1}'


def test_shell_orchestrator_verifies_and_appends_each_record(tmp_path):
    from pathlib import Path
    from subprocess import run

    from cryptography.hazmat.primitives import serialization

    root = Path(__file__).resolve().parents[1]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = tmp_path / "signing.pem"
    public_path = tmp_path / "signing.pub"
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    output_path = tmp_path / "attestation.json"
    ledger_path = tmp_path / "ledger.jsonl"
    command = [
        str(root / "scripts/attest.sh"), "generate",
        "--pr", "123", "--actor", "ai-bot", "--approver", "alice@example.com",
        "--commit", "abcdef123", "--key", str(private_path),
        "--pubkey", str(public_path), "--out", str(output_path),
        "--policy-id", "policy-001", "--risk-score", "8",
        "--rationale", "Policy checks passed",
    ]

    for _ in range(2):
        result = run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "AUDIT_LEDGER": str(ledger_path)},
        )
        assert result.returncode == 0, result.stderr
    records = ledger_path.read_text(encoding="utf-8").splitlines()
    assert len(records) == 2
    assert all(json.loads(record)["pr_id"] == 123 for record in records[-2:])
