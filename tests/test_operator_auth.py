import sqlite3

import pytest

from governed_autonomy.operator_auth import OperatorKeyStore


def test_operator_key_store_persists_hashes_and_revocation(tmp_path):
    path = tmp_path / "operator-keys.sqlite"
    store = OperatorKeyStore(path)
    other_instance = OperatorKeyStore(path)
    created = store.create("alice")

    assert store.authenticate(created["token"]).operator_id == "alice"
    assert other_instance.authenticate(created["token"]).operator_id == "alice"
    with sqlite3.connect(path) as connection:
        token_hash = connection.execute(
            "SELECT token_hash FROM operator_api_keys WHERE key_id = ?",
            (created["key_id"],),
        ).fetchone()[0]
    assert created["token"] not in token_hash
    assert len(token_hash) == 64

    other_instance.revoke(created["key_id"])
    assert store.authenticate(created["token"]) is None
    reopened = OperatorKeyStore(path)
    assert reopened.list_keys()[0]["revoked"] is True
    reopened.close()
    other_instance.close()
    store.close()


def test_operator_key_store_rejects_invalid_and_duplicate_revocation(tmp_path):
    store = OperatorKeyStore(tmp_path / "operator-keys.sqlite")
    created = store.create("alice")

    assert store.authenticate("gasop_" + created["key_id"] + ".wrong") is None
    with pytest.raises(KeyError, match="unknown operator key"):
        store.revoke("missing")
    store.revoke(created["key_id"])
    with pytest.raises(ValueError, match="already revoked"):
        store.revoke(created["key_id"])
    store.close()


def test_operator_key_store_rejects_invalid_persisted_schema(tmp_path):
    path = tmp_path / "operator-keys.sqlite"
    path.write_text("not a sqlite database", encoding="utf-8")
    with pytest.raises(sqlite3.DatabaseError):
        OperatorKeyStore(path)
