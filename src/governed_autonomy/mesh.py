"""Deterministic governance-mesh preflight aggregation."""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
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
    ) -> None:
        if trusted_sources is not None and trust_store is not None:
            raise ValueError("provide either trusted_sources or trust_store, not both")
        self.replay_log = replay_log
        self.trust_store = trust_store
        self.trusted_sources = dict(trusted_sources or {})
        if self.trust_store is not None:
            self.trusted_sources = {
                key_id: key for key_id, key in self.trust_store._keys.items() if key_id not in self.trust_store._revoked
            }

    def _verify_source_attestation(self, item: GovernanceInput) -> None:
        if not self.trusted_sources and self.trust_store is None:
            return
        key = self.trusted_sources.get(item.source_id)
        if key is None and self.trust_store is not None:
            key = self.trust_store.resolve(item.source_id)
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
