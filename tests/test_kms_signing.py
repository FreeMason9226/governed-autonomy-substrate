from governed_autonomy import (
    GovernanceService,
    ImmutableKeyAuditLog,
    KMSHSMBackedSigner,
    KeyPair,
    ReplayLog,
)


def test_kms_signer_never_accepts_private_key_and_audits_rotation():
    key = KeyPair.generate("kms-key-1")
    events = []
    signer = KMSHSMBackedSigner(
        key.key_id,
        lambda payload: key.private_key.sign(payload),
        key.public_key_bytes(),
        audit_hook=lambda event, details: events.append((event, details)),
    )
    service = GovernanceService(signer=signer, replay_log=ReplayLog(), attestor=key)
    payload = b"payload"
    attestation = service._internal_attestation(
        subject=key.key_id,
        role="governance-signer",
        operation="issue-gaa",
        evidence=payload.decode(),
        nonce="n-1",
    )

    assert service.sign_gaa(subject=key.key_id, payload=payload, attestation=attestation)
    assert not hasattr(signer, "private_key")
    signer.rotate(public_key=key.public_key_bytes(), key_id="kms-key-2")
    assert [event for event, _ in events] == ["kms.sign", "kms.rotate"]


def test_kms_rotation_scheduler_is_idempotent_and_append_only():
    first = KeyPair.generate("first")
    second = KeyPair.generate("second")
    audit = ImmutableKeyAuditLog()
    signer = KMSHSMBackedSigner(
        first.key_id, lambda payload: first.private_key.sign(payload), first.public_key_bytes(), audit_log=audit
    )
    assert not signer.rotate_if_due(
        now=100, last_rotated_at=90, interval_seconds=20, fetch_next_key=lambda: (second.key_id, second.public_key_bytes())
    )
    assert signer.rotate_if_due(
        now=120, last_rotated_at=90, interval_seconds=20, fetch_next_key=lambda: (second.key_id, second.public_key_bytes())
    )
    assert [entry.operation for entry in audit.entries] == ["kms.rotate"]
    assert signer.key_id == second.key_id


def test_newly_signed_payload_verifies_after_rotation():
    first = KeyPair.generate("first")
    second = KeyPair.generate("second")
    current = {"key": first}
    signer = KMSHSMBackedSigner(
        first.key_id,
        lambda payload: current["key"].private_key.sign(payload),
        first.public_key_bytes(),
    )
    signer.rotate(public_key=second.public_key_bytes(), key_id=second.key_id)
    current["key"] = second
    signature = signer.sign(b"rotated-payload")
    from governed_autonomy.crypto import verify_signature

    assert verify_signature(second.public_key, b"rotated-payload", signature)