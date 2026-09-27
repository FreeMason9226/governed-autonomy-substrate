from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from governed_autonomy import GovernanceAuthorizationArtifact, KMSSigner, verify_signature


def test_kms_signer_uses_backend_signature_and_public_key_bytes():
    private_key = Ed25519PrivateKey.generate()

    class FakeKMS:
        def sign(self, key_id, payload):
            assert key_id == "kms-key-1"
            return private_key.sign(payload)

        def public_key_bytes(self, key_id):
            assert key_id == "kms-key-1"
            return private_key.public_key().public_bytes_raw()

    signer = KMSSigner("kms-key-1", FakeKMS())
    payload = b"operationally undeniable"

    assert verify_signature(
        private_key.public_key(),
        payload,
        signer.sign(payload),
    )
    assert signer.public_key_bytes() == private_key.public_key().public_bytes_raw()


def test_kms_signer_rejects_invalid_backend():
    try:
        KMSSigner("bad", object())
        raise AssertionError("expected invalid KMS backend to raise")
    except ValueError:
        pass


def test_kms_signer_can_issue_a_governance_artifact():
    private_key = Ed25519PrivateKey.generate()

    class FakeKMS:
        def sign(self, key_id, payload):
            return private_key.sign(payload)

    signer = KMSSigner(
        "kms-key-2",
        FakeKMS(),
        public_key=private_key.public_key().public_bytes_raw(),
    )
    artifact = GovernanceAuthorizationArtifact.issue(
        action_request={"action": "read"},
        decision={"allow": True},
        expires_at=2_000_000_000,
        nonce="kms-nonce",
        replay_frame_ref="authorization:kms-nonce",
        issuer=signer,
    )

    assert artifact.issuer_key_id == "kms-key-2"
    assert verify_signature(
        private_key.public_key(),
        artifact.unsigned_payload(),
        artifact.signature,
    )
