import pytest

from governed_autonomy import (
    AuthorizationIssuer,
    GovernanceAttestation,
    GovernanceService,
    KeyPair,
    Policy,
    ReplayLog,
)
from governed_autonomy.errors import AuthorizationError


def test_execution_node_cannot_sign_gaa_or_write_replay_frames():
    governance_key = KeyPair.generate("governance-signer")
    node_key = KeyPair.generate("execution-node")
    service = GovernanceService(signer=governance_key, replay_log=ReplayLog())
    payload = b'{"allow":true}'
    forged = GovernanceAttestation.issue(
        subject=governance_key.key_id,
        role="execution-node",
        operation="issue-gaa",
        evidence=payload.decode(),
        nonce="node-1",
        signer=node_key,
    )

    with pytest.raises(AuthorizationError):
        service.sign_gaa(subject=governance_key.key_id, payload=payload, attestation=forged)

    replay_forgery = GovernanceAttestation.issue(
        subject="node-1",
        role="execution-writer",
        operation="append-replay",
        evidence={"frame_id": "f-1", "event": {"type": "execution"}},
        nonce="node-2",
        signer=node_key,
    )
    with pytest.raises(AuthorizationError):
        service.append_replay(
            subject="node-1",
            frame_id="f-1",
            event={"type": "execution"},
            attestation=replay_forgery,
        )
    assert service.replay_log.frames == ()


def test_governance_attestation_allows_only_matching_operation_and_evidence():
    key = KeyPair.generate("governance")
    service = GovernanceService(signer=key, replay_log=ReplayLog())
    evidence = {"frame_id": "f-1", "event": {"type": "authorization"}}
    attestation = GovernanceAttestation.issue(
        subject="governance",
        role="governance-writer",
        operation="append-replay",
        evidence=evidence,
        nonce="n-1",
        signer=key,
    )

    frame = service.append_replay(
        subject="governance", frame_id="f-1", event=evidence["event"], attestation=attestation
    )
    assert frame.frame_id == "f-1"


def test_authorization_issuer_uses_hardened_service_endpoints():
    key = KeyPair.generate("governance")
    replay = ReplayLog()
    service = GovernanceService(signer=key, replay_log=replay)


    def test_attestation_is_single_use_and_time_bounded():
        key = KeyPair.generate("governance")
        service = GovernanceService(signer=key, replay_log=ReplayLog(), clock=lambda: 100)
        evidence = {"frame_id": "f-1", "event": {"type": "authorization"}}
        attestation = GovernanceAttestation.issue(
            subject="governance",
            role="governance-writer",
            operation="append-replay",
            evidence=evidence,
            nonce="n-1",
            signer=key,
            issued_at=100,
            ttl_seconds=10,
        )
        service.append_replay(
            subject="governance", frame_id="f-1", event=evidence["event"], attestation=attestation
        )
        with pytest.raises(AuthorizationError, match="already been used"):
            service.append_replay(
                subject="governance", frame_id="f-2", event=evidence["event"], attestation=attestation
            )
    artifact = AuthorizationIssuer(
        governance_service=service, nonce_factory=lambda: "service-nonce"
    ).authorize(
        {"action": "read"},
        Policy("read-v1", ("read",), {"read": ()}, {}),
    )
    assert artifact.issuer_key_id == key.key_id
    assert replay.get("authorization:service-nonce") is not None