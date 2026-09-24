import math

from governed_autonomy import (
    anchor_frame,
    cid_for_hash,
    compact_record,
    entropy_normalized_confidence,
    verify_anchor,
    uuid_frame_hash,
    verify_compact_record,
)


def test_uuid_is_embedded_in_frame_hash_and_cid_is_reproducible():
    event = {"type": "authorization", "nonce": "n-1"}
    first = uuid_frame_hash("uuid-1", "frame-1", "", event)
    second = uuid_frame_hash("uuid-2", "frame-1", "", event)
    assert first != second
    assert cid_for_hash(first).startswith("b")
    assert cid_for_hash(first) == cid_for_hash(first)


def test_independent_verifier_can_verify_ledger_anchor():
    event = {"type": "execution", "status": "completed"}
    anchor = anchor_frame("uuid-1", "frame-1", "", event)
    assert verify_anchor(anchor, "frame-1", "", event)
    assert not verify_anchor(anchor, "frame-1", "", {"type": "execution", "status": "failed"})
    record = compact_record(anchor, {"selected_source": "arbiter-a", "allow": True})
    assert verify_compact_record(record, anchor, {"selected_source": "arbiter-a", "allow": True})
    assert not verify_compact_record(record, anchor, {"selected_source": "arbiter-b", "allow": True})


def test_claim_51a_entropy_normalized_confidence_formula():
    assert entropy_normalized_confidence((1.0, 0.0)) == 1.0
    assert math.isclose(entropy_normalized_confidence((0.5, 0.5)), 0.0)
    entropy = -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25))
    assert math.isclose(entropy_normalized_confidence((0.75, 0.25)), 1 - entropy / math.log2(2))