"""Signed multi-organization governance synchronization and reconciliation."""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from .crypto import KeyPair, verify_signature
from .policy import PolicyRegistry, SignedPolicyManifest, signed_policy_manifest_from_dict
from .trust import TrustStore


class FederationError(ValueError):
    """Raised when a federation message cannot be safely accepted."""


@dataclass(frozen=True)
class SignedSyncEvent:
    event_type: str
    source_org: str
    target_org: str
    snapshot_digest: str
    policy_digests: dict[str, str]
    issued_at: int
    nonce: str
    signer_key_id: str
    signature: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "source_org": self.source_org,
            "target_org": self.target_org,
            "snapshot_digest": self.snapshot_digest,
            "policy_digests": dict(sorted(self.policy_digests.items())),
            "issued_at": self.issued_at,
            "nonce": self.nonce,
            "signer_key_id": self.signer_key_id,
        }

    def unsigned_payload(self) -> bytes:
        return canonical_json(self.unsigned_dict())

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "signature": self.signature}

    @classmethod
    def issue(
        cls,
        *,
        event_type: str,
        source_org: str,
        target_org: str,
        snapshot_digest: str,
        policy_digests: dict[str, str],
        nonce: str,
        signer: KeyPair,
        issued_at: int | None = None,
    ) -> "SignedSyncEvent":
        if not event_type or not source_org or not target_org or not snapshot_digest or not nonce:
            raise ValueError("event type, organizations, snapshot digest, and nonce are required")
        unsigned = cls(
            event_type, source_org, target_org, snapshot_digest,
            dict(sorted(policy_digests.items())), int(time.time()) if issued_at is None else issued_at,
            nonce, signer.key_id, "",
        )
        return cls(**{**unsigned.__dict__, "signature": signer.sign(unsigned.unsigned_payload())})

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SignedSyncEvent":
        required = {
            "event_type", "source_org", "target_org", "snapshot_digest", "policy_digests",
            "issued_at", "nonce", "signer_key_id", "signature",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise FederationError("sync event has an invalid schema")
        if not all(isinstance(value[key], str) and value[key] for key in required - {"policy_digests", "issued_at"}):
            raise FederationError("sync event contains invalid string fields")
        if not isinstance(value["issued_at"], int) or isinstance(value["issued_at"], bool):
            raise FederationError("sync event issued_at must be an integer")
        if not isinstance(value["policy_digests"], dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in value["policy_digests"].items()
        ):
            raise FederationError("sync event policy digests are invalid")
        return cls(
            event_type=value["event_type"], source_org=value["source_org"], target_org=value["target_org"],
            snapshot_digest=value["snapshot_digest"], policy_digests=dict(sorted(value["policy_digests"].items())),
            issued_at=value["issued_at"], nonce=value["nonce"], signer_key_id=value["signer_key_id"],
            signature=value["signature"],
        )

    def verify(self, trust_store: TrustStore, *, now: int | None = None, max_age_seconds: int = 3600) -> None:
        if self.event_type not in {"policy_update", "registry_update"}:
            raise FederationError("unsupported sync event type")
        if self.issued_at <= 0 or (now is not None and self.issued_at > now + 30):
            raise FederationError("sync event timestamp is invalid")
        if now is not None and now - self.issued_at > max_age_seconds:
            raise FederationError("sync event is stale")
        key = trust_store.resolve(self.signer_key_id)
        if key is None or not verify_signature(key, self.unsigned_payload(), self.signature):
            raise FederationError("sync event signature is invalid or untrusted")


@dataclass(frozen=True)
class RegistrySnapshot:
    source_org: str
    version: int
    policies: dict[str, dict[str, Any]]
    policy_digests: dict[str, str]
    snapshot_digest: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "source_org": self.source_org,
            "version": self.version,
            "policies": {key: self.policies[key] for key in sorted(self.policies)},
            "policy_digests": dict(sorted(self.policy_digests.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "snapshot_digest": self.snapshot_digest}

    @classmethod
    def from_registry(cls, registry: PolicyRegistry, *, source_org: str, version: int = 1) -> "RegistrySnapshot":
        policies = {entry["policy"]["policy_id"]: entry for entry in registry.to_dict()["policies"]}
        digests = registry.digests()
        unsigned = {
            "version": version,
            "policies": {key: policies[key] for key in sorted(policies)},
            "policy_digests": dict(sorted(digests.items())),
        }
        return cls(source_org, version, policies, digests, hashlib.sha256(canonical_json(unsigned)).hexdigest())

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RegistrySnapshot":
        required = {"source_org", "version", "policies", "policy_digests", "snapshot_digest"}
        if not isinstance(value, dict) or set(value) != required or not isinstance(value["policies"], dict) or not isinstance(value["policy_digests"], dict):
            raise FederationError("registry snapshot has an invalid schema")
        candidate = cls(value["source_org"], value["version"], value["policies"], value["policy_digests"], value["snapshot_digest"])
        expected = hashlib.sha256(canonical_json(candidate.unsigned_dict())).hexdigest()
        if expected != candidate.snapshot_digest:
            raise FederationError("registry snapshot digest does not match contents")
        if set(candidate.policies) != set(candidate.policy_digests):
            raise FederationError("registry snapshot policy IDs and digests differ")
        for policy_id, entry in candidate.policies.items():
            if not isinstance(entry, dict) or entry.get("policy", {}).get("policy_id") != policy_id:
                raise FederationError("registry snapshot contains an unstable policy ID")
        return candidate


@dataclass(frozen=True)
class GovernanceSyncEnvelope:
    event: SignedSyncEvent
    snapshot: RegistrySnapshot
    signature: str

    def unsigned_payload(self) -> bytes:
        return canonical_json({"event": self.event.to_dict(), "snapshot": self.snapshot.to_dict()})

    def to_dict(self) -> dict[str, Any]:
        return {"event": self.event.to_dict(), "snapshot": self.snapshot.to_dict(), "signature": self.signature}

    @classmethod
    def issue(cls, event: SignedSyncEvent, snapshot: RegistrySnapshot, signer: KeyPair) -> "GovernanceSyncEnvelope":
        unsigned = cls(event, snapshot, "")
        return cls(event, snapshot, signer.sign(unsigned.unsigned_payload()))

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "GovernanceSyncEnvelope":
        if not isinstance(value, dict) or set(value) != {"event", "snapshot", "signature"}:
            raise FederationError("sync envelope has an invalid schema")
        if not isinstance(value["signature"], str) or not value["signature"]:
            raise FederationError("sync envelope signature is required")
        return cls(SignedSyncEvent.from_dict(value["event"]), RegistrySnapshot.from_dict(value["snapshot"]), value["signature"])

    def verify(self, trust_store: TrustStore, *, now: int | None = None, max_age_seconds: int = 3600) -> None:
        self.event.verify(trust_store, now=now, max_age_seconds=max_age_seconds)
        if self.event.source_org != self.snapshot.source_org or self.event.snapshot_digest != self.snapshot.snapshot_digest:
            raise FederationError("sync event does not bind the supplied snapshot")
        key = trust_store.resolve(self.event.signer_key_id)
        if key is None or not verify_signature(key, self.unsigned_payload(), self.signature):
            raise FederationError("sync envelope signature is invalid or untrusted")


@dataclass(frozen=True)
class ReconciliationResult:
    status: str
    imported_policy_ids: tuple[str, ...] = ()
    conflicts: tuple[dict[str, str], ...] = ()
    metadata: dict[str, Any] | None = None


class GovernanceReconciler:
    def __init__(
        self,
        *,
        local_org: str,
        registry: PolicyRegistry,
        trust_store: TrustStore,
        organization_keys: dict[str, str],
        now: Any = time.time,
        max_event_age_seconds: int = 3600,
    ) -> None:
        self.local_org = local_org
        self.registry = registry
        self.trust_store = trust_store
        self.organization_keys = dict(organization_keys)
        self.now = now
        self.max_event_age_seconds = max_event_age_seconds
        self._seen_nonces: set[tuple[str, str]] = set()

    def reconcile(self, envelope: GovernanceSyncEnvelope) -> ReconciliationResult:
        now = int(self.now())
        expected_key = self.organization_keys.get(envelope.event.source_org)
        if expected_key is None or expected_key != envelope.event.signer_key_id:
            raise FederationError("sync event source organization is unknown or signer is not registered")
        if envelope.event.target_org != self.local_org:
            raise FederationError("sync event target organization does not match local organization")
        replay_key = (envelope.event.source_org, envelope.event.nonce)
        if replay_key in self._seen_nonces:
            raise FederationError("sync event nonce has already been consumed")
        envelope.verify(self.trust_store, now=now, max_age_seconds=self.max_event_age_seconds)
        if envelope.event.policy_digests != envelope.snapshot.policy_digests:
            raise FederationError("sync event policy digests do not match snapshot")
        self._seen_nonces.add(replay_key)

        local = RegistrySnapshot.from_registry(self.registry, source_org=self.local_org, version=envelope.snapshot.version)
        if local.snapshot_digest == envelope.snapshot.snapshot_digest:
            return ReconciliationResult("identical", metadata={"snapshot_digest": local.snapshot_digest})

        conflicts: list[dict[str, str]] = []
        imports: list[str] = []
        for policy_id, entry in envelope.snapshot.policies.items():
            remote_digest = envelope.snapshot.policy_digests[policy_id]
            remote_policy = entry.get("policy")
            if not isinstance(remote_policy, dict):
                raise FederationError("remote policy entry is invalid")
            from .policy import policy_from_dict
            parsed = policy_from_dict(remote_policy)
            if parsed.digest() != remote_digest:
                raise FederationError(f"remote policy digest mismatch: {policy_id}")
            existing = self.registry.get(policy_id)
            if existing is not None:
                if existing.digest() != remote_digest:
                    conflicts.append({"policy_id": policy_id, "local_digest": existing.digest(), "remote_digest": remote_digest})
                continue
            if "signature" not in entry:
                raise FederationError(f"unknown policy {policy_id} is not signed")
            manifest = signed_policy_manifest_from_dict(entry)
            if manifest.policy.digest() != remote_digest or not manifest.verify(self.trust_store):
                raise FederationError(f"unknown policy {policy_id} has invalid manifest signature")
            self.registry.register_signed(manifest, self.trust_store)
            imports.append(policy_id)
        if conflicts:
            return ReconciliationResult("conflict", tuple(imports), tuple(conflicts), {"source_org": envelope.event.source_org})
        if self.registry.path is not None:
            self.registry.save()
        return ReconciliationResult("adopted", tuple(sorted(imports)), metadata={"source_org": envelope.event.source_org, "snapshot_digest": envelope.snapshot.snapshot_digest})

