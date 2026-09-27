from governed_autonomy import KeyPair, KMSHSMBackedSigner
from governed_autonomy.crypto import verify_signature


def test_rotation_preserves_new_signature_verification():
    old = KeyPair.generate("old")
    new = KeyPair.generate("new")
    active = {"key": old}
    signer = KMSHSMBackedSigner(
        old.key_id,
        lambda payload: active["key"].private_key.sign(payload),
        old.public_key_bytes(),
    )
    signer.rotate(public_key=new.public_key_bytes(), key_id=new.key_id)
    active["key"] = new
    signature = signer.sign(b"new-key-payload")
    assert verify_signature(new.public_key, b"new-key-payload", signature)