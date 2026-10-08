import base64
import os
import uuid
from pathlib import Path

import pytest

from governed_autonomy import KeyPair, PostgresReplayLog, build_runtime_service


@pytest.fixture
def postgres_url() -> str:
    value = os.environ.get("GAS_POSTGRES_TEST_URL")
    if not value:
        pytest.skip("GAS_POSTGRES_TEST_URL is not configured")
    return value


def test_postgres_runtime_survives_restart_and_rejects_reused_nonce(
    postgres_url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    issuer = KeyPair.generate("integration-issuer")
    encoded = base64.urlsafe_b64encode(issuer.private_key.private_bytes_raw()).decode()
    trust_path = tmp_path / "trust.json"
    monkeypatch.setenv("GAS_RUNTIME_MODE", "postgres")
    monkeypatch.setenv("DATABASE_URL", postgres_url)
    monkeypatch.setenv("GAS_ISSUER_KEY_ID", issuer.key_id)
    monkeypatch.setenv("GAS_ISSUER_PRIVATE_KEY", encoded)
    monkeypatch.setenv("TRUST_STORE_PATH", str(trust_path))

    service, _, replay_log = build_runtime_service()
    artifact = service.authorize(
        {"action": "write_file", "path": "out.txt", "content": "postgres"},
        "demo-files-v1",
    )
    assert service.execute(artifact) == "postgres"
    service.boundary.trust_store.revoke(issuer.key_id)
    replay_log.close()

    import psycopg

    restarted = PostgresReplayLog(psycopg.connect(postgres_url))
    assert restarted.verify_chain()
    assert restarted.nonce_used(artifact.nonce)
    assert restarted.get(artifact.replay_frame_ref) is not None
    assert restarted.connection.execute(
        "SELECT revoked FROM trust_keys WHERE key_id=%s", (issuer.key_id,)
    ).fetchone()[0] is True
    with pytest.raises(ValueError, match="already consumed"):
        restarted.claim_nonce(artifact.nonce)
    restarted.close()


def test_postgres_failure_does_not_report_a_successful_claim(postgres_url: str) -> None:
    import psycopg

    replay_log = PostgresReplayLog(psycopg.connect(postgres_url))
    replay_log.connection.close()
    with pytest.raises(psycopg.Error):
        replay_log.claim_nonce("database-outage-nonce")


def test_postgres_replay_integrity_refreshes_from_another_connection(postgres_url: str) -> None:
    import psycopg

    primary = PostgresReplayLog(psycopg.connect(postgres_url))
    observer = PostgresReplayLog(psycopg.connect(postgres_url))
    try:
        before = observer.verify_integrity()["frame_count"]
        primary.append(
            f"refresh-{uuid.uuid4().hex}",
            {"type": "governance", "event": "cross_connection_refresh"},
        )

        report = observer.verify_integrity()

        assert report["ok"] is True
        assert report["frame_count"] == before + 1
    finally:
        primary.close()
        observer.close()
