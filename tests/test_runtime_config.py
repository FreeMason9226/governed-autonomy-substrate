import base64

import pytest

from governed_autonomy import KeyPair, build_runtime_service


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
        "TRUST_STORE_PATH",
    ):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(RuntimeError, match="required in postgres runtime mode"):
        build_runtime_service()


def test_key_pair_loads_raw_base64_private_key():
    key = KeyPair.generate("test")
    encoded = base64.urlsafe_b64encode(key.private_key.private_bytes_raw()).decode()
    loaded = KeyPair.from_private_key_b64("test", encoded)
    assert loaded.public_key_bytes() == key.public_key_bytes()
