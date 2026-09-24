"""Deterministic UUID-bound frame hashing, CID generation, and ledger proofs."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json


def uuid_frame_hash(frame_uuid: str, frame_id: str, previous_hash: str, event: dict[str, Any]) -> str:
    body = {
        "frame_uuid": frame_uuid,
        "frame_id": frame_id,
        "previous_hash": previous_hash,
        "event": event,
    }
    return hashlib.sha256(canonical_json(body)).hexdigest()


def cid_for_hash(frame_hash: str) -> str:
    digest = bytes.fromhex(frame_hash)
    cid_bytes = b"\x01\x55\x12\x20" + digest
    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")


@dataclass(frozen=True)
class LedgerAnchor:
    frame_uuid: str
    frame_hash: str
    cid: str
    previous_anchor: str


@dataclass(frozen=True)
class LedgerCompactRecord:
    frame_uuid: str
    frame_cid: str
    frame_hash: str
    arbiter_selection_digest: str
    previous_record: str = ""


def anchor_frame(
    frame_uuid: str, frame_id: str, previous_hash: str, event: dict[str, Any], previous_anchor: str = ""
) -> LedgerAnchor:
    frame_hash = uuid_frame_hash(frame_uuid, frame_id, previous_hash, event)
    return LedgerAnchor(frame_uuid, frame_hash, cid_for_hash(frame_hash), previous_anchor)


def verify_anchor(
    anchor: LedgerAnchor, frame_id: str, previous_hash: str, event: dict[str, Any]
) -> bool:
    expected_hash = uuid_frame_hash(anchor.frame_uuid, frame_id, previous_hash, event)
    return anchor.frame_hash == expected_hash and anchor.cid == cid_for_hash(expected_hash)


def compact_record(anchor: LedgerAnchor, arbiter_selection: Any, previous_record: str = "") -> LedgerCompactRecord:
    selection_digest = hashlib.sha256(canonical_json(arbiter_selection)).hexdigest()
    return LedgerCompactRecord(
        frame_uuid=anchor.frame_uuid,
        frame_cid=anchor.cid,
        frame_hash=anchor.frame_hash,
        arbiter_selection_digest=selection_digest,
        previous_record=previous_record,
    )


def verify_compact_record(record: LedgerCompactRecord, anchor: LedgerAnchor, arbiter_selection: Any) -> bool:
    expected = compact_record(anchor, arbiter_selection, record.previous_record)
    return record == expected