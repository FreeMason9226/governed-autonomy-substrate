"""Independently verify the published UUID, SHA-256, CID, and compact-record vector."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def cid_for_hash(frame_hash: str) -> str:
    raw = b"\x01\x55\x12\x20" + bytes.fromhex(frame_hash)
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def verify(path: Path) -> None:
    vector = json.loads(path.read_text(encoding="utf-8"))
    body = {
        "event": vector["event"],
        "frame_id": vector["frame_id"],
        "frame_uuid": vector["frame_uuid"],
        "previous_hash": vector["previous_hash"],
    }
    frame_hash = hashlib.sha256(canonical_json(body)).hexdigest()
    if frame_hash != vector["frame_hash"] or cid_for_hash(frame_hash) != vector["cid"]:
        raise SystemExit("anchor verification failed")
    print(f"frame hash: {frame_hash}")
    print(f"CID: {vector['cid']}")
    print("anchor verification: OK")


if __name__ == "__main__":
    verify(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("docs/cryptographic_vectors.json"))