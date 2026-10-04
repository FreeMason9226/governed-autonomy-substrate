"""Versioned policy schema validation and immutable policy registry."""

import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path
from typing import Any, Protocol

from jsonschema import Draft202012Validator

from .canonical import canonical_json

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


@cache
def load_policy_schema() -> dict[str, Any]:
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
    return hashlib.sha256(canonical_json(policy)).hexdigest()


@dataclass(frozen=True)
class StoredPolicy:
    id: str
    version: str
    content_hash: str
    policy: dict[str, Any]


class PolicyStorage(Protocol):
    def get(self, policy_id: str, version: str) -> StoredPolicy | None: ...

    def put(self, stored: StoredPolicy) -> None: ...

    def versions(self, policy_id: str) -> list[str]: ...


class InMemoryPolicyStorage:
    def __init__(self) -> None:
        self._data: dict[tuple[str, str], StoredPolicy] = {}

    def get(self, policy_id: str, version: str) -> StoredPolicy | None:
        return self._data.get((policy_id, version))

    def put(self, stored: StoredPolicy) -> None:
        self._data[(stored.id, stored.version)] = stored

    def versions(self, policy_id: str) -> list[str]:
        return [v for (pid, v) in self._data if pid == policy_id]


class FilePolicyStorage:
    """Stores each version at ``<root>/<id>/<version>.json``; files are never rewritten."""

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
        record = json.loads(path.read_text(encoding="utf-8"))
        return StoredPolicy(policy_id, version, record["content_hash"], record["policy"])

    def put(self, stored: StoredPolicy) -> None:
        path = self._path(stored.id, stored.version)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"content_hash": stored.content_hash, "policy": stored.policy}
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(record))
            os.chmod(tmp, 0o444)
            # link() fails if the target exists, so a version can never be overwritten.
            os.link(tmp, path)
        except FileExistsError:
            existing = self.get(stored.id, stored.version)
            if existing is None or existing.content_hash != stored.content_hash:
                raise PolicyImmutabilityError(
                    f"policy {stored.id}@{stored.version} already exists with different content"
                ) from None
        finally:
            os.unlink(tmp)

    def versions(self, policy_id: str) -> list[str]:
        if not _ID_RE.match(policy_id):
            return []
        directory = self._root / policy_id
        if not directory.is_dir():
            return []
        return [p.stem for p in directory.glob("*.json") if _SEMVER_RE.match(p.stem)]


class VersionedPolicyRegistry:
    def __init__(self, storage: PolicyStorage | None = None) -> None:
        self._storage: PolicyStorage = storage if storage is not None else InMemoryPolicyStorage()
        self._lock = threading.Lock()

    def register(self, policy: Mapping[str, Any]) -> StoredPolicy:
        validate_policy(policy)
        content = json.loads(canonical_json(policy))
        stored = StoredPolicy(content["id"], content["version"], policy_hash(content), content)
        with self._lock:
            existing = self._storage.get(stored.id, stored.version)
            if existing is not None:
                if existing.content_hash != stored.content_hash:
                    raise PolicyImmutabilityError(
                        f"policy {stored.id}@{stored.version} already exists with different content"
                    )
                return existing
            self._storage.put(stored)
        return stored

    def get(self, policy_id: str, version: str) -> StoredPolicy:
        stored = self._storage.get(policy_id, version)
        if stored is None:
            raise PolicyNotFoundError(f"{policy_id}@{version}")
        return stored

    def list_versions(self, policy_id: str) -> list[str]:
        """Versions in ascending SemVer order."""
        return sorted(self._storage.versions(policy_id), key=semver_key)

    def latest(self, policy_id: str) -> StoredPolicy:
        versions = self.list_versions(policy_id)
        if not versions:
            raise PolicyNotFoundError(policy_id)
        return self.get(policy_id, versions[-1])
