"""Independent compact-record and replay-frame verifier CLI."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def cid_for_hash(frame_hash: str) -> str:
    multihash = b"\x12\x20" + bytes.fromhex(frame_hash)
    return "b" + base64.b32encode(b"\x01\x55" + multihash).decode("ascii").lower().rstrip("=")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def verify_replay(record: dict[str, Any], frame: dict[str, Any], selection: dict[str, Any]) -> None:
    frame_body = {
        "event": frame["event"],
        "frame_id": frame["frame_id"],
        "frame_uuid": frame["frame_uuid"],
        "previous_hash": frame["previous_hash"],
    }
    frame_hash = sha256_json(frame_body)
    if frame_hash != record["frame_hash"]:
        raise ValueError("off-chain frame hash does not match compact record")
    if cid_for_hash(frame_hash) != record["frame_cid"]:
        raise ValueError("computed CID does not match on-chain CID")
    if sha256_json(selection) != record["arbiter_selection_digest"]:
        raise ValueError("arbiter selection proof does not match compact record")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, required=True, help="compact ledger record JSON")
    parser.add_argument("--frame", type=Path, required=True, help="off-chain replay frame JSON")
    parser.add_argument("--selection", type=Path, required=True, help="arbiter selection proof JSON")
    args = parser.parse_args()
    verify_replay(
        json.loads(args.record.read_text(encoding="utf-8")),
        json.loads(args.frame.read_text(encoding="utf-8")),
        json.loads(args.selection.read_text(encoding="utf-8")),
    )
    print("frame hash: verified")
    print("on-chain CID: verified")
    print("arbiter selection proof: verified")
    print("replay verification: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())