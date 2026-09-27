"""Deterministic governance-mesh preflight aggregation."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64decode, b64encode, canonical_json
from .crypto import KeyPair, verify_signature
from .replay import ReplayLog
from .trust import TrustStore


class GovernanceMeshError(ValueError):
    """Raised when governance-mesh evidence is malformed or unsafe."""


@dataclass(frozen=True)
class GovernanceInput:
    """One canonical governance decision supplied by a named governance source."""

    source_id: str
    decision: Mapping[str, Any]
    weight: int = 1
    priority: int = 0
    metadata: Mapping[str, Any] | None = None
    source_signature: str | None = None

    def __post_init__(self) -> None:
        if not self.source_id or not isinstance(self.source_id, str):
            raise GovernanceMeshError("source_id must be a non-empty string")
        if not isinstance(self.decision, Mapping) or not self.decision:
            raise GovernanceMeshError("decision must be a non-empty mapping")
        try:
            canonical_json(dict(self.decision))
        except (TypeError, ValueError) as exc:
            raise GovernanceMeshError("decision must contain canonical JSON values") from exc
        if not isinstance(self.weight, int) or isinstance(self.weight, bool) or self.weight <= 0:
            raise GovernanceMeshError("weight must be a positive integer")
        if not isinstance(self.priority, int) or isinstance(self.priority, bool) or self.priority < 0:
            raise GovernanceMeshError("priority must be a non-negative integer")
        if self.metadata is not None and not isinstance(self.metadata, Mapping):
            raise GovernanceMeshError("metadata must be a mapping when present")
        if not isinstance(self.decision.get("allow"), bool):
            raise GovernanceMeshError("decision.allow must be a boolean")
        if self.source_signature is not None and (
            not isinstance(self.source_signature, str) or not self.source_signature
        ):
            raise GovernanceMeshError("source_signature must be a non-empty string when present")

    def canonical_decision(self) -> dict[str, Any]:
        return dict(self.decision)

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.canonical_decision())).hexdigest()

    def attestation_payload(self) -> bytes:
        return canonical_json(
            {
                "source_id": self.source_id,
                "decision": self.canonical_decision(),
                "weight": self.weight,
                "priority": self.priority,
                "metadata": dict(self.metadata or {}),
            }
        )

    def attest(self, signer: KeyPair) -> GovernanceInput:
        return GovernanceInput(
            source_id=self.source_id,
            decision=self.decision,
            weight=self.weight,
            priority=self.priority,
            metadata=self.metadata,
            source_signature=signer.sign(self.attestation_payload()),
        )

    def to_dict(self) -> dict[str, Any]:
        value = {
            "source_id": self.source_id,
            "decision": self.canonical_decision(),
            "weight": self.weight,
            "priority": self.priority,
            "metadata": dict(self.metadata or {}),
            "decision_digest": self.digest(),
        }
        if self.source_signature is not None:
            value["source_signature"] = self.source_signature
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> GovernanceInput:
        if not isinstance(value, Mapping):
            raise GovernanceMeshError("governance input must be an object")
        expected = {"source_id", "decision", "weight", "priority", "metadata", "decision_digest"}
        if not set(value).issubset(expected | {"source_signature"}) or not expected.issubset(value):
            raise GovernanceMeshError("governance input has an invalid schema")
        item = cls(
            source_id=value["source_id"],
            decision=value["decision"],
            weight=value["weight"],
            priority=value["priority"],
            metadata=value["metadata"],
            source_signature=value.get("source_signature"),
        )
        if value["decision_digest"] != item.digest():
            raise GovernanceMeshError("governance input digest does not match evidence")
        return item


@dataclass(frozen=True)
class GovernancePreflightDecision:
    """Stable, auditable result of aggregating governance-mesh inputs."""

    allow: bool
    status: str
    selected_digest: str | None
    selected_source_ids: tuple[str, ...]
    input_digests: dict[str, str]
    conflicts: tuple[dict[str, Any], ...]
    reasons: tuple[str, ...]
    digest: str
    replay_frame_ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow": self.allow,
            "status": self.status,
            "selected_digest": self.selected_digest,
            "selected_source_ids": list(self.selected_source_ids),
            "input_digests": dict(sorted(self.input_digests.items())),
            "conflicts": [dict(item) for item in self.conflicts],
            "reasons": list(self.reasons),
            "digest": self.digest,
            "replay_frame_ref": self.replay_frame_ref,
        }


class GovernanceSourceRegistry:
    """Trusted governance-source registry with explicit registration and rotation."""

    def __init__(
        self,
        *,
        trust_store: TrustStore | None = None,
        path: str | Path | None = None,
    ) -> None:
        self.trust_store = trust_store
        self.path = Path(path) if path else None
        self._keys: dict[str, Any] = {}
        self._metadata: dict[str, Mapping[str, Any]] = {}
        self._revoked: set[str] = set()
        if self.path and self.path.exists():
            self._load()

    @staticmethod
    def _coerce_public_key(public_key: Any) -> Ed25519PublicKey:
        if isinstance(public_key, Ed25519PublicKey):
            return public_key
        if isinstance(public_key, str):
            try:
                return Ed25519PublicKey.from_public_bytes(b64decode(public_key))
            except Exception as exc:  # pragma: no cover - defensive conversion
                raise GovernanceMeshError("public_key string is not valid base64 Ed25519 bytes") from exc
        raise GovernanceMeshError("public_key must be an Ed25519 public key or a base64-encoded string")

    def register(
        self,
        source_id: str,
        public_key: Any,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if not source_id or not isinstance(source_id, str):
            raise GovernanceMeshError("source_id must be a non-empty string")
        if public_key is None:
            raise GovernanceMeshError("public_key must not be null")
        self._keys[source_id] = self._coerce_public_key(public_key)
        self._metadata[source_id] = dict(metadata or {})
        self._revoked.discard(source_id)
        self._save()

    def revoke(self, source_id: str) -> None:
        if source_id not in self._keys:
            raise GovernanceMeshError(f"unknown governance source: {source_id}")
        self._revoked.add(source_id)
        self._save()

    def resolve(self, source_id: str) -> Any | None:
        if source_id in self._revoked:
            return None
        if self.trust_store is not None:
            key = self.trust_store.resolve(source_id)
            if key is not None:
                return key
        return self._keys.get(source_id)

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            reloaded = self.from_dict(payload, trust_store=self.trust_store)
        except (OSError, json.JSONDecodeError, GovernanceMeshError, TypeError, ValueError) as exc:
            raise GovernanceMeshError("source registry could not be loaded safely") from exc
        self._keys = reloaded._keys
        self._metadata = reloaded._metadata
        self._revoked = reloaded._revoked

    def to_dict(self) -> dict[str, Any]:
        return {
            "sources": {
                source_id: {
                    "public_key": b64encode(public_key.public_bytes_raw()),
                    "metadata": dict(self._metadata.get(source_id, {})),
                }
                for source_id, public_key in sorted(self._keys.items())
            },
            "revoked": sorted(self._revoked),
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, Any],
        *,
        trust_store: TrustStore | None = None,
    ) -> GovernanceSourceRegistry:
        if not isinstance(value, Mapping):
            raise GovernanceMeshError("source registry must be an object")
        if not {"sources", "revoked"}.issubset(value):
            raise GovernanceMeshError("source registry has an invalid schema")
        registry = cls(trust_store=trust_store)
        if not isinstance(value["sources"], Mapping):
            raise GovernanceMeshError("source registry sources must be an object")
        if not isinstance(value["revoked"], list):
            raise GovernanceMeshError("source registry revoked must be a list")
        for source_id, metadata in value["sources"].items():
            if not isinstance(source_id, str) or not source_id:
                raise GovernanceMeshError("source registry contains an invalid source ID")
            if not isinstance(metadata, Mapping):
                raise GovernanceMeshError("source registry source metadata must be an object")
            public_key = metadata.get("public_key")
            if public_key is None:
                raise GovernanceMeshError(f"source {source_id} is missing a public key")
            try:
                key = registry._coerce_public_key(public_key)
            except GovernanceMeshError as exc:
                raise GovernanceMeshError(f"source {source_id} has an invalid public key") from exc
            registry.register(source_id, key, metadata=metadata.get("metadata", {}))
        for source_id in value["revoked"]:
            if not isinstance(source_id, str) or not source_id:
                raise GovernanceMeshError("source registry contains an invalid revoked source ID")
            registry.revoke(source_id)
        return registry


class GovernanceMesh:
    """Aggregate independent governance inputs without hidden state or nondeterminism.

    Inputs are grouped by exact canonical decision. The highest weighted group wins;
    priority breaks equal-weight ties. If the highest-priority sources disagree on
    allow/deny, the result is explicitly conflicted and fail-closed rather than
    silently choosing a source.
    """

    def __init__(
        self,
        *,
        replay_log: ReplayLog | None = None,
        trusted_sources: Mapping[str, Any] | None = None,
        trust_store: TrustStore | None = None,
        source_registry: GovernanceSourceRegistry | None = None,
    ) -> None:
        if trusted_sources is not None and trust_store is not None:
            raise ValueError("provide either trusted_sources or trust_store, not both")
        if source_registry is not None and (trusted_sources is not None or trust_store is not None):
            raise ValueError("provide either a source registry or key map/trust store, not both")
        self.replay_log = replay_log
        self.trust_store = trust_store
        self.source_registry = source_registry
        self.trusted_sources = dict(trusted_sources or {})
        if self.trust_store is not None:
            self.trusted_sources = {
                key_id: key for key_id, key in self.trust_store._keys.items() if key_id not in self.trust_store._revoked
            }

    def _verify_source_attestation(self, item: GovernanceInput) -> None:
        if self.source_registry is not None:
            key = self.source_registry.resolve(item.source_id)
        elif self.trust_store is not None:
            key = self.trust_store.resolve(item.source_id)
        else:
            key = self.trusted_sources.get(item.source_id)
        if not self.trusted_sources and self.trust_store is None and self.source_registry is None:
            return
        if key is None or item.source_signature is None or not verify_signature(
            key, item.attestation_payload(), item.source_signature
        ):
            raise GovernanceMeshError(
                f"governance source attestation is invalid: {item.source_id}"
            )

    def preflight(
        self,
        inputs: tuple[GovernanceInput, ...] | list[GovernanceInput],
        *,
        request_digest: str,
        replay_frame_ref: str | None = None,
    ) -> GovernancePreflightDecision:
        if not isinstance(request_digest, str) or not request_digest:
            raise GovernanceMeshError("request_digest must be a non-empty string")
        if not inputs:
            raise GovernanceMeshError("at least one governance input is required")
        normalized = tuple(inputs)
        for item in normalized:
            self._verify_source_attestation(item)
        source_ids = [item.source_id for item in normalized]
        if len(set(source_ids)) != len(source_ids):
            raise GovernanceMeshError("source IDs must be unique per preflight")

        input_digests = {item.source_id: item.digest() for item in sorted(normalized, key=lambda x: x.source_id)}
        top_priority = max(item.priority for item in normalized)
        top_inputs = tuple(item for item in normalized if item.priority == top_priority)
        conflicts: list[dict[str, Any]] = []
        for source in sorted(top_inputs, key=lambda item: item.source_id):
            for other in sorted(top_inputs, key=lambda item: item.source_id):
                if source.source_id >= other.source_id:
                    continue
                if source.digest() != other.digest():
                    conflicts.append({
                        "source_ids": [source.source_id, other.source_id],
                        "left_digest": source.digest(),
                        "right_digest": other.digest(),
                        "left_allow": source.decision["allow"],
                        "right_allow": other.decision["allow"],
                        "priority": top_priority,
                    })

        groups: dict[str, list[GovernanceInput]] = {}
        for item in normalized:
            groups.setdefault(item.digest(), []).append(item)
        ranked = sorted(
            groups.items(),
            key=lambda pair: (
                -max(item.priority for item in pair[1]),
                -sum(item.weight for item in pair[1]),
                pair[0],
            ),
        )
        winning_digest, winning_inputs = ranked[0]
        winning_allow = bool(winning_inputs[0].decision["allow"])
        unresolved = len({item.digest() for item in top_inputs}) > 1
        if unresolved:
            status = "conflict"
            allow = False
            reasons = ("highest-priority governance sources provide conflicting decisions",)
            selected_digest = None
            selected_source_ids: tuple[str, ...] = ()
        else:
            status = "allow" if winning_allow else "deny"
            allow = winning_allow
            reasons = tuple(str(reason) for reason in winning_inputs[0].decision.get("reasons", ()))
            selected_digest = winning_digest
            selected_source_ids = tuple(sorted(item.source_id for item in winning_inputs))

        unsigned = {
            "request_digest": request_digest,
            "allow": allow,
            "status": status,
            "selected_digest": selected_digest,
            "selected_source_ids": list(selected_source_ids),
            "input_digests": dict(sorted(input_digests.items())),
            "conflicts": conflicts,
            "reasons": list(reasons),
            "replay_frame_ref": replay_frame_ref,
        }
        decision_digest = hashlib.sha256(canonical_json(unsigned)).hexdigest()
        frame_ref = replay_frame_ref
        if self.replay_log is not None:
            frame_ref = frame_ref or f"mesh-{decision_digest}"
            self.replay_log.append(
                frame_ref,
                {
                    "type": "governance_preflight",
                    "request_digest": request_digest,
                    "decision_digest": decision_digest,
                    "decision": unsigned,
                },
            )
        return GovernancePreflightDecision(
            allow=allow,
            status=status,
            selected_digest=selected_digest,
            selected_source_ids=selected_source_ids,
            input_digests=input_digests,
            conflicts=tuple(conflicts),
            reasons=reasons,
            digest=decision_digest,
            replay_frame_ref=frame_ref,
        )
