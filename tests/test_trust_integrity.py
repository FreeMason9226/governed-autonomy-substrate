import json
from pathlib import Path

import pytest

from governed_autonomy import KeyPair, TrustStore


def test_trust_store_rejects_unknown_revoked_key(tmp_path: Path):
    path = tmp_path / "trust.json"
    path.write_text(
        json.dumps({"keys": {}, "revoked": ["missing"]}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="loaded safely"):
        TrustStore(path)


def test_trust_store_rejects_malformed_public_key(tmp_path: Path):
    path = tmp_path / "trust.json"
    path.write_text(
        json.dumps({"keys": {"issuer": "not-a-key"}, "revoked": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="loaded safely"):
        TrustStore(path)


def test_trust_store_replaces_file_atomically(tmp_path: Path):
    path = tmp_path / "trust.json"
    store = TrustStore(path)
    store.add("issuer", KeyPair.generate("issuer").public_key)

    assert path.exists()
    assert not path.with_suffix(".json.tmp").exists()
