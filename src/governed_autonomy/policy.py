import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .crypto import KeyPair, verify_signature
from .models import SignedApproval
from .trust import TrustStore


@dataclass(frozen=True)
class Policy:
    """Deterministic, data-only policy input for authorization arbitration."""

    policy_id: str
    allowed_actions: tuple[str, ...]
    required_fields: dict[str, tuple[str, ...]]
    exact_fields: dict[str, dict[str, Any]]
    required_context: tuple[str, ...] = ()
    exact_context: dict[str, Any] | None = None
    max_request_bytes: int = 64 * 1024
    max_ttl_seconds: int = 300
    required_approvals: dict[str, int] = field(default_factory=dict)
    required_mesh_inputs: dict[str, int] = field(default_factory=dict)
    required_mesh_sources: dict[str, tuple[str, ...]] = field(default_factory=dict)
    mesh_required_actions: tuple[str, ...] = ()
    mesh_required_environments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.policy_id:
            raise ValueError("policy_id must not be empty")
        if self.max_request_bytes <= 0:
            raise ValueError("max_request_bytes must be positive")
        if self.max_ttl_seconds <= 0:
            raise ValueError("max_ttl_seconds must be positive")
        if any(not isinstance(action, str) or not action for action in self.allowed_actions):
            raise ValueError("allowed_actions must contain non-empty strings")
        if tuple(sorted(self.allowed_actions)) != self.allowed_actions:
            raise ValueError("allowed_actions must be sorted for deterministic output")
        if self.exact_context is None:
            object.__setattr__(self, "exact_context", {})
        if isinstance(self.mesh_required_actions, list):
            object.__setattr__(self, "mesh_required_actions", tuple(self.mesh_required_actions))
        if isinstance(self.mesh_required_environments, list):
            object.__setattr__(self, "mesh_required_environments", tuple(self.mesh_required_environments))
        if isinstance(self.required_mesh_sources, list):
            raise ValueError("required_mesh_sources must map action names to source lists, not a list")
        normalized_sources = {}
        for action, sources in self.required_mesh_sources.items():
            if isinstance(sources, list):
                normalized_sources[action] = tuple(sources)
            elif isinstance(sources, tuple):
                normalized_sources[action] = sources
            else:
                raise ValueError("required_mesh_sources must map action names to a list or tuple of source IDs")
        if normalized_sources != self.required_mesh_sources:
            object.__setattr__(self, "required_mesh_sources", normalized_sources)
        if tuple(sorted(self.required_context)) != self.required_context:
            raise ValueError("required_context must be sorted for deterministic output")
        if any(not isinstance(field, str) or not field for field in self.required_context):
            raise ValueError("required_context must contain non-empty strings")
        for action, fields in self.required_fields.items():
            if not isinstance(action, str) or not action:
                raise ValueError("required_fields action names must be non-empty strings")
            if any(not isinstance(field, str) or not field for field in fields):
                raise ValueError("required_fields must contain non-empty strings")
        for action, fields in self.exact_fields.items():
            if not isinstance(action, str) or not action:
                raise ValueError("exact_fields action names must be non-empty strings")
            if not isinstance(fields, dict):
                raise ValueError("exact_fields constraints must be objects")
        if not isinstance(self.exact_context, dict):
            raise ValueError("exact_context must be an object")
        for action, count in self.required_approvals.items():
            if not isinstance(action, str) or not action:
                raise ValueError("required_approvals action names must be non-empty strings")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError("required_approvals must use non-negative integers")
        for action, count in self.required_mesh_inputs.items():
            if not isinstance(action, str) or not action:
                raise ValueError("required_mesh_inputs action names must be non-empty strings")
            if not isinstance(count, int) or isinstance(count, bool) or count < 0:
                raise ValueError("required_mesh_inputs must use non-negative integers")
        for action, sources in self.required_mesh_sources.items():
            if not isinstance(action, str) or not action:
                raise ValueError("required_mesh_sources action names must be non-empty strings")
            if not isinstance(sources, tuple):
                raise ValueError("required_mesh_sources must map actions to tuples of source IDs")
            if any(not isinstance(source, str) or not source for source in sources):
                raise ValueError("required_mesh_sources must contain only non-empty source IDs")
        if any(not isinstance(action, str) or not action for action in self.mesh_required_actions):
            raise ValueError("mesh_required_actions must contain non-empty strings")
        if tuple(sorted(self.mesh_required_actions)) != self.mesh_required_actions:
            raise ValueError("mesh_required_actions must be sorted for deterministic output")
        if any(not isinstance(environment, str) or not environment for environment in self.mesh_required_environments):
            raise ValueError("mesh_required_environments must contain non-empty strings")
        if tuple(sorted(self.mesh_required_environments)) != self.mesh_required_environments:
            raise ValueError("mesh_required_environments must be sorted for deterministic output")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "policy_id": self.policy_id,
            "allowed_actions": list(self.allowed_actions),
            "required_fields": {
                action: list(fields) for action, fields in sorted(self.required_fields.items())
            },
            "exact_fields": dict(sorted(self.exact_fields.items())),
            "required_context": list(self.required_context),
            "exact_context": self.exact_context,
            "max_request_bytes": self.max_request_bytes,
            "max_ttl_seconds": self.max_ttl_seconds,
            "required_approvals": dict(sorted(self.required_approvals.items())),
        }
        if self.required_mesh_inputs:
            result["required_mesh_inputs"] = dict(sorted(self.required_mesh_inputs.items()))
        if self.required_mesh_sources:
            result["required_mesh_sources"] = {
                action: list(sources)
                for action, sources in sorted(self.required_mesh_sources.items())
            }
        if self.mesh_required_actions:
            result["mesh_required_actions"] = list(self.mesh_required_actions)
        if self.mesh_required_environments:
            result["mesh_required_environments"] = list(self.mesh_required_environments)
        return result

    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.to_dict())).hexdigest()


class DeterministicArbiter:
    """Evaluate a request without I/O, clocks, randomness, or hidden state."""

    def __init__(
        self,
        *,
        issuer_keys: dict[str, Any] | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        if issuer_keys is not None and trust_store is not None:
            raise ValueError("provide either issuer_keys or trust_store, not both")
        self.issuer_keys = issuer_keys or {}
        self.trust_store = trust_store

    def _resolve_public_key(self, key_id: str) -> Any | None:
        if self.trust_store is not None:
            return self.trust_store.resolve(key_id)
        return self.issuer_keys.get(key_id)

    def _approval_count(self, request: dict[str, Any], context: dict[str, Any]) -> int:
        approvers: set[str] = set()
        for container in (request, context):
            if not isinstance(container, dict):
                continue
            for key in ("approval_count", "approvals_count"):
                value = container.get(key)
                if isinstance(value, int) and not isinstance(value, bool):
                    return value
            approvals = container.get("approvals")
            if approvals is None:
                continue
            if not isinstance(approvals, (list, tuple)):
                continue
            for approval in approvals:
                candidate: SignedApproval | None = None
                if isinstance(approval, SignedApproval):
                    candidate = approval
                elif (
                    isinstance(approval, Mapping)
                    and "issuer_key_id" in approval
                    and "signature" in approval
                ):
                        try:
                            candidate = SignedApproval.from_dict(dict(approval))
                        except ValueError:
                            continue
                if candidate is None:
                    continue
                public_key = self._resolve_public_key(candidate.issuer_key_id)
                if public_key is None or not candidate.verify(public_key):
                    continue
                if not candidate.matches_request(request):
                    continue
                approvers.add(candidate.issuer_key_id)
        return len(approvers)

    def decide(self, request: dict[str, Any], policy: Policy) -> dict[str, Any]:
        action = request.get("action")
        context = request.get("context", {})
        reasons: list[str] = []
        reason_codes: list[str] = []
        request_bytes = canonical_json(request)
        if len(request_bytes) > policy.max_request_bytes:
            reasons.append("request exceeds policy size limit")
            reason_codes.append("request_too_large")
        if not isinstance(context, dict):
            reasons.append("context must be an object")
            reason_codes.append("invalid_context")
            context = {}
        allowed = action in policy.allowed_actions
        if not allowed:
            reasons.append("action is not allowed by policy")
            reason_codes.append("action_not_allowed")

        for field_name in policy.required_fields.get(action, ()):
            if field_name not in request:
                reasons.append(f"required field is missing: {field_name}")
                reason_codes.append("required_field_missing")

        for field_name, expected in policy.exact_fields.get(action, {}).items():
            if request.get(field_name) != expected:
                reasons.append(f"field does not match policy: {field_name}")
                reason_codes.append("field_mismatch")

        for context_name in policy.required_context:
            if context_name not in context:
                reasons.append(f"required context is missing: {context_name}")
                reason_codes.append("required_context_missing")
        for context_name, expected in policy.exact_context.items():
            if context.get(context_name) != expected:
                reasons.append(f"context does not match policy: {context_name}")
                reason_codes.append("context_mismatch")

        required_approvals = policy.required_approvals.get(action, 0)
        if required_approvals > 0:
            approval_count = self._approval_count(request, context)
            if approval_count < required_approvals:
                reasons.append(
                    f"approval quorum not met for action {action}: {approval_count} < {required_approvals}"
                )
                reason_codes.append("approval_quorum_not_met")

        return {
            "allow": allowed and not reasons,
            "allowed_actions": list(policy.allowed_actions),
            "policy": policy.policy_id,
            "policy_digest": policy.digest(),
            "reasons": reasons,
            "reason_codes": reason_codes,
            "request_digest": hashlib.sha256(request_bytes).hexdigest(),
        }


class PolicyRegistry:
    """In-process immutable-by-ID policy registry with durable signed-manifest state."""

    def __init__(
        self,
        policies: tuple[Policy, ...] = (),
        path: str | Path | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        self.path = Path(path) if path else None
        self.trust_store = trust_store
        self._policies: dict[str, Policy] = {}
        self._versions: dict[str, int] = {}
        self._signed_manifests: dict[str, SignedPolicyManifest] = {}
        for policy in policies:
            self.register(policy)
        if self.path and self.path.exists():
            self._load()

    def register(self, policy: Policy) -> None:
        existing = self._policies.get(policy.policy_id)
        if existing is not None and existing.digest() != policy.digest():
            raise ValueError(f"policy ID is already registered: {policy.policy_id}")
        self._policies[policy.policy_id] = policy
        self._versions.setdefault(policy.policy_id, 1)

    def register_signed(
        self, manifest: "SignedPolicyManifest", trust_store: TrustStore | None = None
    ) -> None:
        store = trust_store or self.trust_store
        if store is None:
            raise ValueError("a trust store is required to validate a signed policy manifest")
        if not manifest.verify(store):
            raise ValueError("policy manifest signature is invalid or untrusted")
        current = self._policies.get(manifest.policy.policy_id)
        current_version = self._versions.get(manifest.policy.policy_id)
        if current is not None and manifest.version <= current_version:
            if manifest.version == current_version and current.digest() == manifest.policy.digest():
                return
            raise ValueError("policy manifest version is stale or conflicting")
        self.register(manifest.policy)
        self._signed_manifests[manifest.policy.policy_id] = manifest
        self._versions[manifest.policy.policy_id] = manifest.version
        if self.path is not None:
            self._save()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policies": [
                (
                    self._signed_manifests.get(policy_id, None).to_dict()
                    if policy_id in self._signed_manifests
                    else {
                        "policy": policy.to_dict(),
                        "version": self._versions.get(policy_id, 1),
                    }
                )
                for policy_id, policy in sorted(self._policies.items())
            ]
        }

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        trust_store: TrustStore | None = None,
    ) -> "PolicyRegistry":
        if not isinstance(value, dict) or set(value) != {"policies"}:
            raise ValueError("policy registry snapshot has an invalid schema")
        if not isinstance(value["policies"], list):
            raise ValueError("policy registry entries must be a list")
        registry = cls(trust_store=trust_store)
        for entry in value["policies"]:
            if not isinstance(entry, dict):
                raise ValueError("policy registry has an invalid entry schema")
            if "signature" in entry:
                manifest = signed_policy_manifest_from_dict(entry)
                if trust_store is not None and not manifest.verify(trust_store):
                    raise ValueError("persisted policy manifest signature is invalid or untrusted")
                registry.register_signed(manifest, trust_store)
                continue
            if set(entry) != {"policy", "version"}:
                raise ValueError("policy registry has an invalid entry schema")
            policy = policy_from_dict(entry["policy"])
            version = entry["version"]
            if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
                raise ValueError("policy registry version must be a positive integer")
            registry._policies[policy.policy_id] = policy
            registry._versions[policy.policy_id] = version
        return registry

    def save(self) -> None:
        if self.path is None:
            return
        self._save()

    def _save(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = self.to_dict()
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def _load(self) -> None:
        if not self.path or not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("policy registry could not be loaded safely") from exc
        if not isinstance(payload, dict) or set(payload) != {"policies"}:
            raise ValueError("policy registry has an invalid schema")
        if not isinstance(payload["policies"], list):
            raise ValueError("policy registry entries must be a list")

        self._policies.clear()
        self._versions.clear()
        self._signed_manifests.clear()
        for entry in payload["policies"]:
            if not isinstance(entry, dict):
                raise ValueError("policy registry has an invalid entry schema")
            if "signature" in entry:
                manifest = signed_policy_manifest_from_dict(entry)
                if self.trust_store is not None and not manifest.verify(self.trust_store):
                    raise ValueError("persisted policy manifest signature is invalid or untrusted")
                self._signed_manifests[manifest.policy.policy_id] = manifest
                self._policies[manifest.policy.policy_id] = manifest.policy
                self._versions[manifest.policy.policy_id] = manifest.version
                continue
            if set(entry) != {"policy", "version"}:
                raise ValueError("policy registry has an invalid entry schema")
            policy = policy_from_dict(entry["policy"])
            version = entry["version"]
            if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
                raise ValueError("policy registry version must be a positive integer")
            self._policies[policy.policy_id] = policy
            self._versions[policy.policy_id] = version

    def versions(self) -> dict[str, int]:
        return dict(sorted(self._versions.items()))

    def get(self, policy_id: str) -> Policy | None:
        return self._policies.get(policy_id)

    def digests(self) -> dict[str, str]:
        return {policy_id: policy.digest() for policy_id, policy in sorted(self._policies.items())}

    def policies(self) -> tuple[Policy, ...]:
        return tuple(self._policies[policy_id] for policy_id in sorted(self._policies))


@dataclass(frozen=True)
class SignedPolicyManifest:
    policy: Policy
    version: int
    issuer_key_id: str
    signature: str

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "policy": self.policy.to_dict(),
                "version": self.version,
                "issuer_key_id": self.issuer_key_id,
            }
        )

    @classmethod
    def issue(cls, policy: Policy, version: int, issuer: KeyPair) -> "SignedPolicyManifest":
        if version <= 0:
            raise ValueError("manifest version must be positive")
        unsigned = cls(policy, version, issuer.key_id, "")
        return cls(policy, version, issuer.key_id, issuer.sign(unsigned.unsigned_payload()))

    def verify(self, trust_store: TrustStore) -> bool:
        if self.version <= 0:
            return False
        key = trust_store.resolve(self.issuer_key_id)
        return key is not None and verify_signature(key, self.unsigned_payload(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy.to_dict(),
            "version": self.version,
            "issuer_key_id": self.issuer_key_id,
            "signature": self.signature,
        }


def policy_from_dict(value: dict[str, Any]) -> Policy:
    if not isinstance(value, dict):
        raise ValueError("policy must be an object")
    required = {
        "policy_id",
        "allowed_actions",
        "required_fields",
        "exact_fields",
        "required_context",
        "exact_context",
        "max_request_bytes",
        "max_ttl_seconds",
    }
    valid_keys = required | {"required_approvals"}
    if not set(value).issubset(valid_keys):
        raise ValueError("policy manifest has an invalid schema")
    if not set(value).issuperset(required):
        raise ValueError("policy manifest has an invalid schema")
    return Policy(
        policy_id=value["policy_id"],
        allowed_actions=tuple(value["allowed_actions"]),
        required_fields={
            action: tuple(fields) for action, fields in value["required_fields"].items()
        },
        exact_fields=value["exact_fields"],
        required_context=tuple(value["required_context"]),
        exact_context=value["exact_context"],
        max_request_bytes=value["max_request_bytes"],
        max_ttl_seconds=value["max_ttl_seconds"],
        required_approvals=value.get("required_approvals", {}),
    )


def signed_policy_manifest_from_dict(value: dict[str, Any]) -> SignedPolicyManifest:
    if not isinstance(value, dict) or set(value) != {
        "policy",
        "version",
        "issuer_key_id",
        "signature",
    }:
        raise ValueError("policy manifest has an invalid schema")
    if not isinstance(value["version"], int) or isinstance(value["version"], bool):
        raise ValueError("manifest version must be an integer")
    if not isinstance(value["issuer_key_id"], str) or not value["issuer_key_id"]:
        raise ValueError("manifest issuer_key_id must be a non-empty string")
    if not isinstance(value["signature"], str) or not value["signature"]:
        raise ValueError("manifest signature must be a non-empty string")
    return SignedPolicyManifest(
        policy=policy_from_dict(value["policy"]),
        version=value["version"],
        issuer_key_id=value["issuer_key_id"],
        signature=value["signature"],
    )
