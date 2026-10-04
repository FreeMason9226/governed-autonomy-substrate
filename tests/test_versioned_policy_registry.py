import copy
import json
import os
import stat
from pathlib import Path

import pytest

from governed_autonomy.policy_registry import (
    FilePolicyStorage,
    PolicyImmutabilityError,
    PolicyNotFoundError,
    PolicyValidationError,
    VersionedPolicyRegistry,
    policy_hash,
    semver_key,
    validate_policy,
)

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = sorted((ROOT / "examples" / "policies").glob("*.json"))


def make(version: str = "1.0.0", **extra):
    policy = {"id": "p1", "name": "P", "version": version, "description": "d"}
    policy.update(extra)
    return policy


def test_examples_exist_and_validate():
    names = {p.stem for p in EXAMPLES}
    assert {"rate-limit", "allowed-actions", "escalation", "combined"} <= names
    for path in EXAMPLES:
        validate_policy(json.loads(path.read_text()))


def test_schema_file_at_repo_root_matches_package():
    root_schema = json.loads((ROOT / "schemas" / "policy.schema.json").read_text())
    from governed_autonomy.policy_registry import load_policy_schema

    assert root_schema == load_policy_schema()


def test_valid_minimal_policy():
    validate_policy(make())


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("version"),
        lambda p: p.pop("id"),
        lambda p: p.update(version="1.0"),
        lambda p: p.update(version="01.0.0"),
        lambda p: p.update(unknown=1),
        lambda p: p.update(rate_limits=[{"action": "a", "max_requests": 0, "window_seconds": 1}]),
        lambda p: p.update(rate_limits=[{"action": "a", "max_requests": 1, "window_seconds": 1, "x": 1}]),
        lambda p: p.update(allowed_actions={}),
        lambda p: p.update(allowed_actions={"allow": ["a", "a"]}),
        lambda p: p.update(escalation_rules=[{"id": "r", "condition": {}, "escalate_to": "x"}]),
        lambda p: p.update(escalation_rules=[{"id": "r", "condition": {"min_risk_score": 2}, "escalate_to": "x"}]),
    ],
)
def test_invalid_policies(mutate):
    policy = make()
    mutate(policy)
    with pytest.raises(PolicyValidationError):
        validate_policy(policy)


def test_register_validates():
    with pytest.raises(PolicyValidationError):
        VersionedPolicyRegistry().register({"id": "p1"})


def test_idempotent_and_hash():
    reg = VersionedPolicyRegistry()
    first = reg.register(make())
    second = reg.register(copy.deepcopy(make()))
    assert first == second
    assert first.content_hash == policy_hash(make())
    assert len(first.content_hash) == 64


def test_immutability_enforced():
    reg = VersionedPolicyRegistry()
    reg.register(make())
    with pytest.raises(PolicyImmutabilityError):
        reg.register(make(description="changed"))
    assert reg.get("p1", "1.0.0").policy["description"] == "d"


def test_semver_ordering():
    order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
             "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.2.0", "1.10.0", "2.0.0"]
    assert sorted([*order[3:], *order[:3]], key=semver_key) == order
    assert semver_key("1.0.0+a") == semver_key("1.0.0+b")
    with pytest.raises(ValueError):
        semver_key("1.0")


def test_lookup_latest_and_list():
    reg = VersionedPolicyRegistry()
    for v in ["1.10.0", "1.2.0", "2.0.0-rc.1", "1.9.9"]:
        reg.register(make(v))
    assert reg.list_versions("p1") == ["1.2.0", "1.9.9", "1.10.0", "2.0.0-rc.1"]
    assert reg.latest("p1").version == "2.0.0-rc.1"
    assert reg.get("p1", "1.2.0").version == "1.2.0"
    with pytest.raises(PolicyNotFoundError):
        reg.get("p1", "9.9.9")
    with pytest.raises(PolicyNotFoundError):
        reg.latest("missing")
    assert reg.list_versions("missing") == []


def test_file_storage(tmp_path):
    reg = VersionedPolicyRegistry(FilePolicyStorage(tmp_path))
    stored = reg.register(make("1.0.0"))
    reg.register(make("1.1.0"))
    reg2 = VersionedPolicyRegistry(FilePolicyStorage(tmp_path))
    assert reg2.latest("p1").version == "1.1.0"
    assert reg2.get("p1", "1.0.0").content_hash == stored.content_hash
    assert reg2.register(make("1.0.0")) == stored
    with pytest.raises(PolicyImmutabilityError):
        reg2.register(make("1.0.0", description="other"))
    path = tmp_path / "p1" / "1.0.0.json"
    assert not os.access(path, os.W_OK) or os.geteuid() == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o444
    assert [p.name for p in (tmp_path / "p1").iterdir() if p.suffix == ".tmp"] == []
