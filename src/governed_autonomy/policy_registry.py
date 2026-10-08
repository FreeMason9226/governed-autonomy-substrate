"""Immutable, signed, semantic-versioned policy registry boundaries."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

from .canonical import canonical_json
from .crypto import verify_signature
from .rbac import ClaimsIdentity, Role, require_roles
from .signing import LocalEd25519Signer
from .trust import TrustStore

POLICY_RECORD_SCHEMA_VERSION = "1.0"
POLICY_SIGNATURE_ALGORITHM = "ed25519"
MAX_POLICY_BYTES = 1024 * 1024
MAX_POLICY_RECORD_BYTES = MAX_POLICY_BYTES + 8192
_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?$"
)
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


class PolicyValidationError(ValueError):
    """Raised when a policy does not satisfy the policy schema."""


class PolicyImmutabilityError(ValueError):
    """Raised when registering different content for an existing (id, version)."""


class PolicyNotFoundError(KeyError):
    """Raised when a policy id or version is not registered."""


class PolicyIntegrityError(ValueError):
    """Raised when a stored policy no longer matches its recorded digest."""


class PolicySignatureError(ValueError):
    """Raised when a policy signature is missing, unsupported, or invalid."""


class PolicyLifecycleError(ValueError):
    """Raised when a requested policy lifecycle transition is invalid."""


class PolicyActivationConflictError(ValueError):
    """Raised when a compare-and-swap activation revision does not match."""


class PolicyLifecycle(StrEnum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    REVOKED = "REVOKED"


@cache
def load_policy_schema() -> dict[str, Any]:
    """Load the strict policy content schema packaged with the library."""
    text = (
        resources.files("governed_autonomy")
        .joinpath("schemas/policy.schema.json")
        .read_text(encoding="utf-8")
    )
    schema: dict[str, Any] = json.loads(text)
    return schema


@cache
def _validator() -> Draft202012Validator:
    schema = load_policy_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def validate_policy(policy: Mapping[str, Any]) -> None:
    """Validate untrusted policy content before canonicalization or signing."""
    if not isinstance(policy, Mapping):
        raise PolicyValidationError("policy must be an object")
    try:
        encoded = canonical_json(policy)
    except (TypeError, ValueError) as exc:
        raise PolicyValidationError("policy is not canonical JSON serializable") from exc
    if len(encoded) > MAX_POLICY_BYTES:
        raise PolicyValidationError(f"policy exceeds {MAX_POLICY_BYTES} byte limit")
    errors = sorted(_validator().iter_errors(policy), key=lambda e: list(map(str, e.path)))
    if errors:
        details = "; ".join(
            f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors
        )
        raise PolicyValidationError(details)


def semver_key(version: str) -> tuple[Any, ...]:
    """Sort key following SemVer 2.0.0 precedence (build metadata ignored)."""
    match = _SEMVER_RE.match(version)
    if match is None:
        raise ValueError(f"invalid semantic version: {version!r}")
    major, minor, patch, pre = match.groups()
    if pre is None:
        pre_key: tuple[Any, ...] = (1,)
    else:
        parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
        pre_key = (0, parts)
    return (int(major), int(minor), int(patch), pre_key)


def policy_hash(policy: Mapping[str, Any]) -> str:
    """Return the SHA-256 digest of canonical policy content."""
    return hashlib.sha256(canonical_json(policy)).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class PolicySignature:
    """Signature metadata bound to exact canonical policy content and publication data."""

    signer_id: str
    algorithm: str
    signature: str
    signed_at: str


class PolicySigner(Protocol):
    """Signing boundary that can be fulfilled by local, KMS, or HSM implementations."""

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> str: ...


class PolicyVerifier(Protocol):
    """Verification boundary that resolves only trusted public signing identities."""

    def verify(self, signer_id: str, algorithm: str, payload: bytes, signature: str) -> bool: ...


class DevelopmentPolicySigner(LocalEd25519Signer):
    """Ephemeral Ed25519 signer for development and tests; never persists a private key."""

    algorithm = POLICY_SIGNATURE_ALGORITHM


class StaticPolicyVerifier:
    """Local verifier for tests and development with explicit public-key provisioning."""

    def __init__(self, public_keys: Mapping[str, Ed25519PublicKey]) -> None:
        self._public_keys = dict(public_keys)

    def verify(self, signer_id: str, algorithm: str, payload: bytes, signature: str) -> bool:
        return (
            algorithm == POLICY_SIGNATURE_ALGORITHM
            and signer_id in self._public_keys
            and verify_signature(self._public_keys[signer_id], payload, signature)
        )


class TrustStorePolicyVerifier:
    """Verifier adapter over the repository trust store for KMS/HSM-compatible signers."""

    def __init__(self, trust_store: TrustStore) -> None:
        self._trust_store = trust_store

    def verify(self, signer_id: str, algorithm: str, payload: bytes, signature: str) -> bool:
        public_key = self._trust_store.resolve(signer_id)
        return (
            algorithm == POLICY_SIGNATURE_ALGORITHM
            and public_key is not None
            and verify_signature(public_key, payload, signature)
        )


@dataclass(frozen=True)
class StoredPolicy:
    """Immutable canonical policy content and publication signature."""

    id: str
    version: str
    content_hash: str
    policy: dict[str, Any]
    schema_version: str = POLICY_RECORD_SCHEMA_VERSION
    signature: PolicySignature | None = None

    def signed_payload(self) -> bytes:
        """Canonical bytes signed by a policy authority, excluding the signature itself."""
        if self.signature is None:
            raise PolicySignatureError("policy has no publication signature")
        return canonical_json(
            {
                "content_digest": self.content_hash,
                "policy": self.policy,
                "policy_id": self.id,
                "schema_version": self.schema_version,
                "signature_algorithm": self.signature.algorithm,
                "signed_at": self.signature.signed_at,
                "signer_id": self.signature.signer_id,
                "version": self.version,
            }
        )


@dataclass(frozen=True)
class PolicyActivationEvent:
    """Append-only activation or rollback decision linked to immutable policy versions."""

    policy_id: str
    previous_version: str | None
    selected_version: str
    requested_by: str
    reason: str
    timestamp: str
    revision: int
    operation: str


@dataclass(frozen=True)
class PolicyVerificationResult:
    """Structured, non-throwing integrity and signature verification result."""

    policy_id: str
    version: str
    valid: bool
    digest_valid: bool
    signature_valid: bool
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "valid": self.valid,
            "digest_valid": self.digest_valid,
            "signature_valid": self.signature_valid,
            "errors": list(self.errors),
        }


class PolicyStorage(Protocol):
    """Immutable policy-content persistence boundary; lifecycle state stays separate."""

    def get(self, policy_id: str, version: str) -> StoredPolicy | None: ...

    def put(self, stored: StoredPolicy) -> None: ...

    def versions(self, policy_id: str) -> list[str]: ...


class InMemoryPolicyStorage:
    """Process-local immutable policy-content storage for unit tests and development."""

    def __init__(self) -> None:
        self._data: dict[tuple[str, str], StoredPolicy] = {}

    def get(self, policy_id: str, version: str) -> StoredPolicy | None:
        return self._data.get((policy_id, version))

    def put(self, stored: StoredPolicy) -> None:
        self._data[(stored.id, stored.version)] = stored

    def versions(self, policy_id: str) -> list[str]:
        return [version for (stored_id, version) in self._data if stored_id == policy_id]


class FilePolicyStorage:
    """Write-once policy records at ``<root>/<id>/<version>.json`` with state snapshots."""

    _STATE_FILENAME = ".policy-registry-state.json"

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)

    def _path(self, policy_id: str, version: str) -> Path:
        if not _ID_RE.match(policy_id) or _SEMVER_RE.match(version) is None:
            raise ValueError("invalid policy id or version")
        return self._root / policy_id / f"{version}.json"

    def get(self, policy_id: str, version: str) -> StoredPolicy | None:
        path = self._path(policy_id, version)
        if not path.is_file():
            return None
        if path.stat().st_size > MAX_POLICY_RECORD_BYTES:
            raise PolicyIntegrityError(f"stored policy record exceeds size limit: {policy_id}@{version}")
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            signature_data = record.get("signature")
            signature = (
                PolicySignature(
                    signer_id=signature_data["signer_id"],
                    algorithm=signature_data["algorithm"],
                    signature=signature_data["signature"],
                    signed_at=signature_data["signed_at"],
                )
                if isinstance(signature_data, dict)
                else None
            )
            return StoredPolicy(
                id=policy_id,
                version=version,
                content_hash=record["content_hash"],
                policy=record["policy"],
                schema_version=record.get("schema_version", POLICY_RECORD_SCHEMA_VERSION),
                signature=signature,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise PolicyIntegrityError(
                f"stored policy record is malformed: {policy_id}@{version}"
            ) from exc

    def put(self, stored: StoredPolicy) -> None:
        path = self._path(stored.id, stored.version)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "content_hash": stored.content_hash,
            "policy": stored.policy,
            "schema_version": stored.schema_version,
            "signature": asdict(stored.signature) if stored.signature is not None else None,
        }
        fd, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(record))
            os.chmod(temporary, 0o444)
            os.link(temporary, path)
        except FileExistsError:
            existing = self.get(stored.id, stored.version)
            if existing is None or existing != stored:
                raise PolicyImmutabilityError(
                    f"policy {stored.id}@{stored.version} already exists"
                ) from None
        finally:
            os.unlink(temporary)

    def versions(self, policy_id: str) -> list[str]:
        if not _ID_RE.match(policy_id):
            return []
        directory = self._root / policy_id
        if not directory.is_dir():
            return []
        return [path.stem for path in directory.glob("*.json") if _SEMVER_RE.match(path.stem)]

    def load_state(self) -> dict[str, Any]:
        path = self._root / self._STATE_FILENAME
        if not path.exists():
            return {}
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyIntegrityError("policy lifecycle state could not be loaded safely") from exc
        if not isinstance(payload, dict):
            raise PolicyIntegrityError("policy lifecycle state must be an object")
        return payload

    def save_state(self, payload: Mapping[str, Any]) -> None:
        self._root.mkdir(parents=True, exist_ok=True)
        path = self._root / self._STATE_FILENAME
        fd, temporary = tempfile.mkstemp(dir=self._root, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(payload))
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


class PolicyRegistry(Protocol):
    """Public registry contract implementable by local, PostgreSQL, or object-store backends."""

    def publish(self, policy: Mapping[str, Any], signer: PolicySigner) -> StoredPolicy: ...

    def get(self, policy_id: str, version: str) -> StoredPolicy: ...

    def get_active(self, policy_id: str) -> StoredPolicy: ...

    def list_versions(self, policy_id: str) -> list[str]: ...

    def verify(self, policy_id: str, version: str) -> PolicyVerificationResult: ...


class VersionedPolicyRegistry:
    """Local reference implementation with immutable content and CAS lifecycle state."""

    def __init__(
        self,
        storage: PolicyStorage | None = None,
        *,
        verifier: PolicyVerifier | None = None,
    ) -> None:
        self._storage: PolicyStorage = storage if storage is not None else InMemoryPolicyStorage()
        self._verifier = verifier
        self._lock = threading.RLock()
        self._states: dict[tuple[str, str], PolicyLifecycle] = {}
        self._active: dict[str, tuple[str, int]] = {}
        self._history: dict[str, list[PolicyActivationEvent]] = {}
        self._load_state()

    @staticmethod
    def _canonical_policy(policy: Mapping[str, Any]) -> dict[str, Any]:
        validate_policy(policy)
        content = json.loads(canonical_json(policy))
        if not isinstance(content, dict):
            raise PolicyValidationError("policy must be an object")
        return content

    @staticmethod
    def _signature_algorithm(signer: PolicySigner) -> str:
        algorithm = getattr(signer, "algorithm", POLICY_SIGNATURE_ALGORITHM)
        if algorithm != POLICY_SIGNATURE_ALGORITHM:
            raise PolicySignatureError(f"unsupported policy signature algorithm: {algorithm!r}")
        return algorithm

    def _new_stored(
        self,
        policy: Mapping[str, Any],
        *,
        signer: PolicySigner | None,
        signed_at: str | None = None,
    ) -> StoredPolicy:
        content = self._canonical_policy(policy)
        unsigned = StoredPolicy(
            id=content["id"],
            version=content["version"],
            content_hash=policy_hash(content),
            policy=content,
        )
        if signer is None:
            return unsigned
        timestamp = signed_at or _utc_now()
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp)
        except (TypeError, ValueError) as exc:
            raise PolicySignatureError("signed_at must be an ISO-8601 UTC timestamp") from exc
        if parsed_timestamp.tzinfo is None or parsed_timestamp.utcoffset() != UTC.utcoffset(None):
            raise PolicySignatureError("signed_at must use the UTC timezone")
        if not signer.key_id:
            raise PolicySignatureError("policy signer identity must not be empty")
        signature = PolicySignature(
            signer_id=signer.key_id,
            algorithm=self._signature_algorithm(signer),
            signature="",
            signed_at=timestamp,
        )
        signing_record = StoredPolicy(**{**unsigned.__dict__, "signature": signature})
        return StoredPolicy(
            **{
                **signing_record.__dict__,
                "signature": PolicySignature(
                    signer_id=signature.signer_id,
                    algorithm=signature.algorithm,
                    signature=signer.sign(signing_record.signed_payload()),
                    signed_at=signature.signed_at,
                ),
            }
        )

    def _copy(self, stored: StoredPolicy) -> StoredPolicy:
        return StoredPolicy(
            id=stored.id,
            version=stored.version,
            content_hash=stored.content_hash,
            policy=copy.deepcopy(stored.policy),
            schema_version=stored.schema_version,
            signature=stored.signature,
        )

    def _verification(self, stored: StoredPolicy) -> PolicyVerificationResult:
        errors: list[str] = []
        digest_valid = stored.schema_version == POLICY_RECORD_SCHEMA_VERSION
        if not digest_valid:
            errors.append("unsupported_record_schema_version")
        try:
            digest_valid = policy_hash(stored.policy) == stored.content_hash and digest_valid
        except (TypeError, ValueError):
            digest_valid = False
        if not digest_valid:
            errors.append("content_digest_mismatch")
        signature_valid = False
        if stored.signature is None:
            errors.append("missing_signature")
        elif self._verifier is None:
            errors.append("no_signature_verifier_configured")
        elif stored.signature.algorithm != POLICY_SIGNATURE_ALGORITHM:
            errors.append("unsupported_signature_algorithm")
        else:
            try:
                signature_valid = self._verifier.verify(
                    stored.signature.signer_id,
                    stored.signature.algorithm,
                    stored.signed_payload(),
                    stored.signature.signature,
                )
            except (TypeError, ValueError, PolicySignatureError):
                signature_valid = False
            if not signature_valid:
                errors.append("signature_invalid")
        return PolicyVerificationResult(
            policy_id=stored.id,
            version=stored.version,
            valid=digest_valid and signature_valid,
            digest_valid=digest_valid,
            signature_valid=signature_valid,
            errors=tuple(errors),
        )

    def register(self, policy: Mapping[str, Any]) -> StoredPolicy:
        """Legacy idempotent registration API retained for backwards compatibility.

        New production callers must use :meth:`publish`, which rejects every duplicate
        publication and requires a verifiable authority signature.
        """
        stored = self._new_stored(policy, signer=None)
        with self._lock:
            existing = self._storage.get(stored.id, stored.version)
            if existing is not None:
                if existing.content_hash != stored.content_hash:
                    raise PolicyImmutabilityError(
                        f"policy {stored.id}@{stored.version} already exists with different content"
                    )
                return self._copy(existing)
            self._storage.put(stored)
            self._states[(stored.id, stored.version)] = PolicyLifecycle.PUBLISHED
            self._save_state()
        return self._copy(stored)

    def publish(
        self,
        policy: Mapping[str, Any],
        signer: PolicySigner,
        *,
        signed_at: str | None = None,
    ) -> StoredPolicy:
        """Publish a signed immutable policy version; duplicate publications are rejected."""
        stored = self._new_stored(policy, signer=signer, signed_at=signed_at)
        with self._lock:
            if self._storage.get(stored.id, stored.version) is not None:
                raise PolicyImmutabilityError(
                    f"policy {stored.id}@{stored.version} is already published"
                )
            verification = self._verification(stored)
            if not verification.valid:
                raise PolicySignatureError("; ".join(verification.errors))
            self._storage.put(stored)
            self._states[(stored.id, stored.version)] = PolicyLifecycle.PUBLISHED
            self._save_state()
        return self._copy(stored)

    def get(self, policy_id: str, version: str) -> StoredPolicy:
        """Load a defensive policy copy only after checking its immutable digest."""
        stored = self._storage.get(policy_id, version)
        if stored is None:
            raise PolicyNotFoundError(f"{policy_id}@{version}")
        verification = self._verification(stored)
        if not verification.digest_valid:
            raise PolicyIntegrityError("; ".join(verification.errors))
        return self._copy(stored)

    def verify(self, policy_id: str, version: str) -> PolicyVerificationResult:
        """Return digest and signature verification evidence without mutating registry state."""
        stored = self._storage.get(policy_id, version)
        if stored is None:
            raise PolicyNotFoundError(f"{policy_id}@{version}")
        return self._verification(stored)

    def list_versions(self, policy_id: str) -> list[str]:
        """Return versions in ascending SemVer precedence order."""
        return sorted(self._storage.versions(policy_id), key=semver_key)

    def latest(self, policy_id: str) -> StoredPolicy:
        versions = self.list_versions(policy_id)
        if not versions:
            raise PolicyNotFoundError(policy_id)
        return self.get(policy_id, versions[-1])

    def lifecycle(self, policy_id: str, version: str) -> PolicyLifecycle:
        self.get(policy_id, version)
        return self._states.get((policy_id, version), PolicyLifecycle.PUBLISHED)

    def list_lifecycle(self, policy_id: str) -> dict[str, PolicyLifecycle]:
        return {
            version: self.lifecycle(policy_id, version) for version in self.list_versions(policy_id)
        }

    def get_active(self, policy_id: str) -> StoredPolicy:
        active = self._active.get(policy_id)
        if active is None:
            raise PolicyNotFoundError(f"no active policy version for {policy_id}")
        version, _ = active
        if self.lifecycle(policy_id, version) != PolicyLifecycle.ACTIVE:
            raise PolicyLifecycleError(f"active policy {policy_id}@{version} is not usable")
        verification = self.verify(policy_id, version)
        if not verification.valid:
            raise PolicySignatureError("; ".join(verification.errors))
        return self.get(policy_id, version)

    def active_revision(self, policy_id: str) -> int:
        return self._active.get(policy_id, ("", 0))[1]

    def activate(
        self,
        policy_id: str,
        version: str,
        *,
        requested_by: str,
        reason: str,
        expected_revision: int | None = None,
        identity: ClaimsIdentity | None = None,
        operation: str = "activate",
    ) -> PolicyActivationEvent:
        """Atomically activate a verified published version using an optional CAS revision."""
        if identity is not None:
            require_roles(identity, (Role.POLICY_ADMIN,))
        if not requested_by or not reason:
            raise PolicyLifecycleError("requested_by and reason are required")
        with self._lock:
            stored = self.get(policy_id, version)
            verification = self._verification(stored)
            if not verification.valid:
                raise PolicySignatureError("; ".join(verification.errors))
            state = self._states.get((policy_id, version), PolicyLifecycle.PUBLISHED)
            if state not in {PolicyLifecycle.PUBLISHED, PolicyLifecycle.ACTIVE}:
                raise PolicyLifecycleError(
                    f"policy {policy_id}@{version} cannot be activated from {state}"
                )
            current = self._active.get(policy_id)
            current_revision = current[1] if current is not None else 0
            if expected_revision is not None and expected_revision != current_revision:
                raise PolicyActivationConflictError(
                    f"expected revision {expected_revision}, current revision is {current_revision}"
                )
            previous_version = current[0] if current is not None else None
            if previous_version == version:
                raise PolicyLifecycleError(f"policy {policy_id}@{version} is already active")
            if previous_version is not None:
                self._states[(policy_id, previous_version)] = PolicyLifecycle.PUBLISHED
            revision = current_revision + 1
            self._states[(policy_id, version)] = PolicyLifecycle.ACTIVE
            self._active[policy_id] = (version, revision)
            event = PolicyActivationEvent(
                policy_id=policy_id,
                previous_version=previous_version,
                selected_version=version,
                requested_by=requested_by,
                reason=reason,
                timestamp=_utc_now(),
                revision=revision,
                operation=operation,
            )
            self._history.setdefault(policy_id, []).append(event)
            self._save_state()
            return event

    def rollback(
        self,
        policy_id: str,
        version: str,
        *,
        requested_by: str,
        reason: str,
        expected_revision: int | None = None,
        identity: ClaimsIdentity | None = None,
    ) -> PolicyActivationEvent:
        """Activate a previously published immutable version without deleting intervening versions."""
        return self.activate(
            policy_id,
            version,
            requested_by=requested_by,
            reason=reason,
            expected_revision=expected_revision,
            identity=identity,
            operation="rollback",
        )

    def deprecate(
        self,
        policy_id: str,
        version: str,
        *,
        identity: ClaimsIdentity | None = None,
    ) -> None:
        """Mark a non-active published version as deprecated without changing its content."""
        if identity is not None:
            require_roles(identity, (Role.POLICY_ADMIN,))
        with self._lock:
            state = self.lifecycle(policy_id, version)
            if state == PolicyLifecycle.ACTIVE:
                raise PolicyLifecycleError("an active policy version cannot be deprecated")
            if state == PolicyLifecycle.REVOKED:
                raise PolicyLifecycleError("a revoked policy version cannot be deprecated")
            self._states[(policy_id, version)] = PolicyLifecycle.DEPRECATED
            self._save_state()

    def revoke(
        self,
        policy_id: str,
        version: str,
        *,
        identity: ClaimsIdentity | None = None,
    ) -> None:
        """Revoke a version and remove it from active selection without deleting evidence."""
        if identity is not None:
            require_roles(identity, (Role.POLICY_ADMIN,))
        with self._lock:
            self.get(policy_id, version)
            self._states[(policy_id, version)] = PolicyLifecycle.REVOKED
            active = self._active.get(policy_id)
            if active is not None and active[0] == version:
                self._active[policy_id] = ("", active[1] + 1)
            self._save_state()

    def activation_history(self, policy_id: str) -> tuple[PolicyActivationEvent, ...]:
        return tuple(self._history.get(policy_id, ()))

    def _load_state(self) -> None:
        loader = getattr(self._storage, "load_state", None)
        if loader is None:
            return
        payload = loader()
        if not payload:
            return
        try:
            states = payload.get("states", {})
            active = payload.get("active", {})
            history = payload.get("history", {})
            if not all(isinstance(value, dict) for value in (states, active, history)):
                raise ValueError("invalid lifecycle state")
            for policy_id, versions in states.items():
                if not isinstance(policy_id, str) or not isinstance(versions, dict):
                    raise ValueError("invalid lifecycle state")
                for version, value in versions.items():
                    self._states[(policy_id, version)] = PolicyLifecycle(value)
            for policy_id, value in active.items():
                if not isinstance(value, dict):
                    raise ValueError("invalid active state")
                version, revision = value["version"], value["revision"]
                if not isinstance(version, str) or not isinstance(revision, int) or revision < 0:
                    raise ValueError("invalid active revision")
                self._active[policy_id] = (version, revision)
            for policy_id, events in history.items():
                if not isinstance(events, list):
                    raise ValueError("invalid activation history")
                self._history[policy_id] = [
                    PolicyActivationEvent(**event) for event in events if isinstance(event, dict)
                ]
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyIntegrityError("policy lifecycle state is malformed") from exc

    def _save_state(self) -> None:
        saver = getattr(self._storage, "save_state", None)
        if saver is None:
            return
        states: dict[str, dict[str, str]] = {}
        for (policy_id, version), state in self._states.items():
            states.setdefault(policy_id, {})[version] = state.value
        saver(
            {
                "states": states,
                "active": {
                    policy_id: {"version": version, "revision": revision}
                    for policy_id, (version, revision) in self._active.items()
                },
                "history": {
                    policy_id: [asdict(event) for event in events]
                    for policy_id, events in self._history.items()
                },
            }
        )
