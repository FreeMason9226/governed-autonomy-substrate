import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json


@dataclass(frozen=True)
class ReplayFrame:
    frame_id: str
    previous_hash: str
    event: dict[str, Any]
    frame_hash: str

    @classmethod
    def create(cls, frame_id: str, previous_hash: str, event: dict[str, Any]) -> "ReplayFrame":
        body = {"frame_id": frame_id, "previous_hash": previous_hash, "event": event}
        frame_hash = hashlib.sha256(canonical_json(body)).hexdigest()
        return cls(frame_id, previous_hash, event, frame_hash)

    def to_dict(self) -> dict[str, Any]:
        return {
            "frame_id": self.frame_id,
            "previous_hash": self.previous_hash,
            "event": self.event,
            "frame_hash": self.frame_hash,
        }


class ReplayLog:
    """Append-only hash-chained replay frames with deterministic lookup."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._frames: list[ReplayFrame] = []
        self._used_nonces: set[str] = set()
        self._lock = threading.RLock()

    @classmethod
    def load_jsonl(cls, path: str | Path) -> "ReplayLog":
        """Reload a JSONL log and reject malformed or broken hash-chain data."""
        log = cls(path)
        source = Path(path)
        if not source.exists():
            return log
        for line_number, line in enumerate(
            source.read_text(encoding="utf-8").splitlines(), start=1
        ):
            try:
                payload = json.loads(line)
                frame = ReplayFrame(
                    payload["frame_id"],
                    payload["previous_hash"],
                    payload["event"],
                    payload["frame_hash"],
                )
            except (KeyError, TypeError, json.JSONDecodeError) as exc:
                raise ValueError(f"invalid replay frame at line {line_number}") from exc
            expected = ReplayFrame.create(frame.frame_id, frame.previous_hash, frame.event)
            if frame.frame_hash != expected.frame_hash:
                raise ValueError(f"invalid frame hash at line {line_number}")
            if frame.previous_hash != (log._frames[-1].frame_hash if log._frames else ""):
                raise ValueError(f"broken replay chain at line {line_number}")
            log._frames.append(frame)
            if frame.event.get("type") == "execution":
                log._used_nonces.add(frame.event["nonce"])
        return log

    def append(self, frame_id: str, event: dict[str, Any]) -> ReplayFrame:
        with self._lock:
            previous_hash = self._frames[-1].frame_hash if self._frames else ""
            frame = ReplayFrame.create(frame_id, previous_hash, event)
            self._frames.append(frame)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(frame.to_dict(), sort_keys=True) + "\n")
            return frame

    def get(self, frame_id: str) -> ReplayFrame | None:
        return next((frame for frame in self._frames if frame.frame_id == frame_id), None)

    def mark_nonce(self, nonce: str) -> None:
        self.claim_nonce(nonce)

    def claim_nonce(self, nonce: str) -> None:
        with self._lock:
            if nonce in self._used_nonces:
                raise ValueError(f"nonce already consumed: {nonce}")
            self._used_nonces.add(nonce)

    def nonce_used(self, nonce: str) -> bool:
        return nonce in self._used_nonces

    @property
    def frames(self) -> tuple[ReplayFrame, ...]:
        return tuple(self._frames)

    def events(self, event_type: str | None = None) -> tuple[dict[str, Any], ...]:
        """Return immutable audit event snapshots, optionally filtered by type."""
        if event_type is not None and not event_type:
            raise ValueError("event_type must not be empty")
        return tuple(
            frame.event
            for frame in self._frames
            if event_type is None or frame.event.get("type") == event_type
        )

    def events_for_nonce(self, nonce: str) -> tuple[dict[str, Any], ...]:
        if not nonce:
            raise ValueError("nonce must not be empty")
        return tuple(frame.event for frame in self._frames if frame.event.get("nonce") == nonce)

    def reconstruct_decisions(self) -> dict[str, dict[str, Any]]:
        """Deterministically reconstruct the authorization state for each nonce."""
        decisions: dict[str, dict[str, Any]] = {}
        for frame in self._frames:
            event = frame.event
            if event.get("type") == "authorization":
                nonce = event.get("nonce")
                if not nonce:
                    continue
                record = decisions.setdefault(
                    str(nonce),
                    {"authorization": None, "execution": None},
                )
                record["authorization"] = {
                    "issued": bool(event.get("issued", False)),
                    "request": event.get("request"),
                    "decision": event.get("decision"),
                    "artifact_payload": event.get("artifact_payload"),
                }
            elif event.get("type") == "execution":
                nonce = event.get("nonce")
                if not nonce:
                    continue
                record = decisions.setdefault(
                    str(nonce),
                    {"authorization": None, "execution": None},
                )
                record["execution"] = {
                    "status": event.get("status"),
                    "result": event.get("result"),
                    "error": event.get("error"),
                    "policy_id": event.get("policy_id"),
                }
        return dict(sorted(decisions.items()))

    def audit_summary(self) -> dict[str, Any]:
        """Return an immutable, deterministic summary of authorization and execution history."""
        decisions = self.reconstruct_decisions()
        authorizations = [event for event in self.events("authorization") if event.get("nonce")]
        executions = [event for event in self.events("execution") if event.get("nonce")]
        return {
            "frame_count": len(self._frames),
            "authorization_count": len(authorizations),
            "execution_count": len(executions),
            "success_count": sum(1 for event in executions if event.get("status") == "completed"),
            "failure_count": sum(1 for event in executions if event.get("status") == "failed"),
            "nonces": sorted(str(event["nonce"]) for event in authorizations + executions),
            "decisions": decisions,
        }

    def verify_chain(self) -> bool:
        previous_hash = ""
        for frame in self._frames:
            expected = ReplayFrame.create(frame.frame_id, previous_hash, frame.event)
            if frame.previous_hash != previous_hash or frame.frame_hash != expected.frame_hash:
                return False
            previous_hash = frame.frame_hash
        return True


class SQLiteReplayLog(ReplayLog):
    """Durable replay log backed by SQLite transactions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._lock = threading.RLock()
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS replay_frames (
                frame_id TEXT PRIMARY KEY,
                previous_hash TEXT NOT NULL,
                event_json TEXT NOT NULL,
                frame_hash TEXT NOT NULL UNIQUE
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS consumed_nonces (
                nonce TEXT PRIMARY KEY
            )
            """
        )
        self._connection.commit()
        self._frames = [
            ReplayFrame(
                row[0],
                row[1],
                json.loads(row[2]),
                row[3],
            )
            for row in self._connection.execute(
                "SELECT frame_id, previous_hash, event_json, frame_hash "
                "FROM replay_frames ORDER BY rowid"
            )
        ]
        self._used_nonces = {
            row[0] for row in self._connection.execute("SELECT nonce FROM consumed_nonces")
        }
        if not self.verify_chain():
            self._connection.close()
            raise ValueError("SQLite replay log contains an invalid hash chain")

    def append(self, frame_id: str, event: dict[str, Any]) -> ReplayFrame:
        with self._lock:
            frame = ReplayFrame.create(
                frame_id,
                self._frames[-1].frame_hash if self._frames else "",
                event,
            )
            try:
                self._connection.execute(
                    "INSERT INTO replay_frames "
                    "(frame_id, previous_hash, event_json, frame_hash) VALUES (?, ?, ?, ?)",
                    (
                        frame.frame_id,
                        frame.previous_hash,
                        json.dumps(event, sort_keys=True, separators=(",", ":")),
                        frame.frame_hash,
                    ),
                )
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise ValueError(f"replay frame already exists: {frame_id}") from exc
            self._frames.append(frame)
            return frame

    def mark_nonce(self, nonce: str) -> None:
        self.claim_nonce(nonce)

    def claim_nonce(self, nonce: str) -> None:
        with self._lock:
            try:
                self._connection.execute("INSERT INTO consumed_nonces (nonce) VALUES (?)", (nonce,))
                self._connection.commit()
            except sqlite3.IntegrityError as exc:
                self._connection.rollback()
                raise ValueError(f"nonce already consumed: {nonce}") from exc
            self._used_nonces.add(nonce)

    def close(self) -> None:
        self._connection.close()
