from pathlib import Path

import pytest

from governed_autonomy import (
    AuthorizationIssuer,
    AuthorizationError,
    ExecutionBoundary,
    KeyPair,
    Policy,
    ReplayLog,
    TrustStore,
)


def test_trust_store_rotation_and_revocation(tmp_path: Path):
    old = KeyPair.generate("issuer-old")
    new = KeyPair.generate("issuer-new")
    store_path = tmp_path / "trust.json"
    store = TrustStore(store_path)
    store.add(old.key_id, old.public_key)
    store.add(new.key_id, new.public_key)
    store.revoke(old.key_id)

    reopened = TrustStore(store_path)
    assert reopened.resolve(old.key_id) is None
    assert reopened.resolve(new.key_id) is not None


def test_revoked_issuer_cannot_execute_existing_artifact():
    issuer = KeyPair.generate("issuer-revoked")
    log = ReplayLog()
    policy = Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {})
    artifact = AuthorizationIssuer(
        issuer=issuer,
        replay_log=log,
        nonce_factory=lambda: "revoked-nonce",
    ).authorize({"action": "write_file", "path": "out.txt"}, policy)
    store = TrustStore()
    store.add(issuer.key_id, issuer.public_key)
    store.revoke(issuer.key_id)

    with pytest.raises(AuthorizationError, match="signature"):
        ExecutionBoundary(
            replay_log=log,
            trust_store=store,
        ).execute(artifact, lambda _: "must not run")
