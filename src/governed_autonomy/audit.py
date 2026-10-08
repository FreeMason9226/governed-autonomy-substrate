"""Signed checkpoints for independently retained replay evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json
from .crypto import verify_signature
from .signing import Signer


@dataclass(frozen=True)
class AuditAnchor:
    """A signed checkpoint of a replay log retained by an independent sink."""

    replay_digest: str
    head_hash: str
    frame_count: int
    signer_key_id: str
    signature: str

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "replay_digest": self.replay_digest,
            "head_hash": self.head_hash,
            "frame_count": self.frame_count,
            "signer_key_id": self.signer_key_id,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "signature": self.signature}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> AuditAnchor:
        required = ("replay_digest", "head_hash", "frame_count", "signer_key_id", "signature")
        if any(key not in payload for key in required):
            raise ValueError("audit anchor is missing required fields")
        replay_digest = payload["replay_digest"]
        head_hash = payload["head_hash"]
        frame_count = payload["frame_count"]
        signer_key_id = payload["signer_key_id"]
        signature = payload["signature"]
        if (
            not isinstance(replay_digest, str)
            or not isinstance(head_hash, str)
            or not isinstance(frame_count, int)
            or isinstance(frame_count, bool)
            or frame_count < 0
            or not isinstance(signer_key_id, str)
            or not isinstance(signature, str)
        ):
            raise ValueError("audit anchor fields are invalid")
        return cls(replay_digest, head_hash, frame_count, signer_key_id, signature)

    def verify(self, public_key: Ed25519PublicKey) -> bool:
        return verify_signature(
            public_key,
            canonical_json(self.unsigned_payload()),
            self.signature,
        )


class AuditAnchorSink(Protocol):
    """A WORM/transparency-log adapter that persists signed checkpoints."""

    def append(self, anchor: AuditAnchor) -> None: ...


class JSONLAuditAnchorSink:
    """Append-only local adapter; use a separately retained path or object store mount."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, anchor: AuditAnchor) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(anchor.to_dict(), sort_keys=True, separators=(",", ":")) + "\n")

    def anchors(self) -> tuple[AuditAnchor, ...]:
        if not self.path.exists():
            return ()
        return tuple(
            AuditAnchor.from_dict(json.loads(line))
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line
        )


def sign_audit_anchor(
    integrity: dict[str, Any],
    signer: Signer,
) -> AuditAnchor:
    replay_digest = integrity.get("replay_digest")
    head_hash = integrity.get("head_hash")
    frame_count = integrity.get("frame_count")
    if (
        integrity.get("ok") is not True
        or not isinstance(replay_digest, str)
        or not isinstance(head_hash, str)
        or not isinstance(frame_count, int)
    ):
        raise ValueError("cannot anchor an invalid replay log")
    unsigned = {
        "replay_digest": replay_digest,
        "head_hash": head_hash,
        "frame_count": frame_count,
        "signer_key_id": signer.key_id,
    }
    return AuditAnchor(
        replay_digest=replay_digest,
        head_hash=head_hash,
        frame_count=frame_count,
        signer_key_id=signer.key_id,
        signature=signer.sign(canonical_json(unsigned)),
    )
