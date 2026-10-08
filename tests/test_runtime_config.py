import base64
import sys
from types import SimpleNamespace

import pytest

from governed_autonomy import KeyPair, KMSSigner, build_runtime_service
from governed_autonomy.bootstrap import _runtime_signer


def test_runtime_memory_mode_is_explicit(monkeypatch):
    monkeypatch.setenv("GAS_RUNTIME_MODE", "memory")
    service, _, replay_log = build_runtime_service()
    assert service.audit_report()["health"]["ok"] is True
    assert replay_log.verify_chain()


def test_runtime_postgres_mode_requires_persistent_configuration(monkeypatch):
    monkeypatch.setenv("GAS_RUNTIME_MODE", "postgres")
    for name in (
        "DATABASE_URL",
        "GAS_ISSUER_KEY_ID",
        "GAS_ISSUER_PRIVATE_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="required in postgres runtime mode"):
        build_runtime_service()


def test_key_pair_loads_raw_base64_private_key():
    key = KeyPair.generate("test")
    encoded = base64.urlsafe_b64encode(key.private_key.private_bytes_raw()).decode()
    loaded = KeyPair.from_private_key_b64("test", encoded)
    assert loaded.public_key_bytes() == key.public_key_bytes()


def test_runtime_signer_uses_aws_kms_with_workload_credentials(monkeypatch):
    monkeypatch.setenv("GAS_ISSUER_SIGNER", "aws-kms")
    monkeypatch.setenv("GAS_ISSUER_KMS_KEY_ID", "alias/gas-issuer")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    fake_client = object()

    def create_client(service, region_name):
        assert service == "kms"
        assert region_name == "us-east-1"
        return fake_client

    monkeypatch.setitem(
        sys.modules,
        "boto3",
        SimpleNamespace(client=create_client),
    )

    signer = _runtime_signer()

    assert isinstance(signer, KMSSigner)
    assert signer.key_id == "alias/gas-issuer"


def test_runtime_signer_rejects_missing_kms_key_id(monkeypatch):
    monkeypatch.setenv("GAS_ISSUER_SIGNER", "aws-kms")
    monkeypatch.delenv("GAS_ISSUER_KMS_KEY_ID", raising=False)

    with pytest.raises(RuntimeError, match="GAS_ISSUER_KMS_KEY_ID"):
        _runtime_signer()
