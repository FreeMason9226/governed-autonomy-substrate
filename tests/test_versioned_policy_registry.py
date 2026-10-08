import copy
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governed_autonomy.policy_registry import (
    DevelopmentPolicySigner,
    FilePolicyStorage,
    InMemoryPolicyStorage,
    PolicyActivationConflictError,
    PolicyImmutabilityError,
    PolicyIntegrityError,
    PolicyLifecycle,
    PolicyLifecycleError,
    PolicyNotFoundError,
    PolicySignatureError,
    PolicyValidationError,
    StaticPolicyVerifier,
    VersionedPolicyRegistry,
    policy_hash,
    semver_key,
    validate_policy,
)
from governed_autonomy.rbac import ClaimsIdentity, Role

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
        lambda p: p.update(
            rate_limits=[{"action": "a", "max_requests": 1, "window_seconds": 1, "x": 1}]
        ),
        lambda p: p.update(allowed_actions={}),
        lambda p: p.update(allowed_actions={"allow": ["a", "a"]}),
        lambda p: p.update(escalation_rules=[{"id": "r", "condition": {}, "escalate_to": "x"}]),
        lambda p: p.update(
            escalation_rules=[{"id": "r", "condition": {"min_risk_score": 2}, "escalate_to": "x"}]
        ),
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
    order = [
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.2.0",
        "1.10.0",
        "2.0.0",
    ]
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


def signed_registry() -> tuple[VersionedPolicyRegistry, DevelopmentPolicySigner]:
    signer = DevelopmentPolicySigner("policy-authority")
    verifier = StaticPolicyVerifier(
        {signer.key_id: Ed25519PublicKey.from_public_bytes(signer.public_key_bytes())}
    )
    return VersionedPolicyRegistry(verifier=verifier), signer


def test_publish_requires_unique_semver_and_valid_signature():
    registry, signer = signed_registry()
    stored = registry.publish(make(), signer)

    assert stored.content_hash == policy_hash(make())
    assert registry.verify("p1", "1.0.0").valid
    with pytest.raises(PolicyImmutabilityError, match="already published"):
        registry.publish(make(), signer)
    with pytest.raises(PolicyValidationError):
        registry.publish(make(version="1.0"), signer)


def test_publish_rejects_signature_without_a_trusted_verifier():
    signer = DevelopmentPolicySigner("untrusted")
    registry = VersionedPolicyRegistry(
        verifier=StaticPolicyVerifier(
            {
                DevelopmentPolicySigner("different").key_id: Ed25519PublicKey.from_public_bytes(
                    signer.public_key_bytes()
                )
            }
        )
    )

    with pytest.raises(PolicySignatureError, match="signature_invalid"):
        registry.publish(make(), signer)


def test_publish_rejects_non_utc_signing_timestamp():
    registry, signer = signed_registry()

    with pytest.raises(PolicySignatureError, match="UTC"):
        registry.publish(make(), signer, signed_at="2026-01-01T00:00:00")


def test_load_detects_policy_content_tampering_and_returns_defensive_copies():
    storage = InMemoryPolicyStorage()
    signer = DevelopmentPolicySigner("policy-authority")
    registry = VersionedPolicyRegistry(
        storage,
        verifier=StaticPolicyVerifier(
            {signer.key_id: Ed25519PublicKey.from_public_bytes(signer.public_key_bytes())}
        ),
    )
    registry.publish(make(), signer)
    loaded = registry.get("p1", "1.0.0")
    loaded.policy["description"] = "caller mutation"
    assert registry.get("p1", "1.0.0").policy["description"] == "d"

    stored = storage.get("p1", "1.0.0")
    assert stored is not None
    storage._data[("p1", "1.0.0")] = replace(
        stored, policy={**stored.policy, "description": "tampered"}
    )
    with pytest.raises(PolicyIntegrityError, match="content_digest_mismatch"):
        registry.get("p1", "1.0.0")


def test_activate_and_rollback_preserve_history():
    registry, signer = signed_registry()
    registry.publish(make("1.0.0"), signer)
    registry.publish(make("1.1.0"), signer)
    first = registry.activate(
        "p1",
        "1.0.0",
        requested_by="alice",
        reason="initial rollout",
        expected_revision=0,
    )
    second = registry.activate(
        "p1",
        "1.1.0",
        requested_by="alice",
        reason="upgrade",
        expected_revision=first.revision,
    )
    rollback = registry.rollback(
        "p1",
        "1.0.0",
        requested_by="bob",
        reason="regression detected",
        expected_revision=second.revision,
    )

    assert registry.get_active("p1").version == "1.0.0"
    assert registry.lifecycle("p1", "1.0.0") == PolicyLifecycle.ACTIVE
    assert registry.lifecycle("p1", "1.1.0") == PolicyLifecycle.PUBLISHED
    assert [
        (event.operation, event.previous_version, event.selected_version)
        for event in registry.activation_history("p1")
    ] == [
        ("activate", None, "1.0.0"),
        ("activate", "1.0.0", "1.1.0"),
        ("rollback", "1.1.0", "1.0.0"),
    ]
    assert rollback.revision == 3


def test_revoked_policy_cannot_be_activated():
    registry, signer = signed_registry()
    registry.publish(make(), signer)
    registry.revoke("p1", "1.0.0")

    assert registry.lifecycle("p1", "1.0.0") == PolicyLifecycle.REVOKED
    with pytest.raises(PolicyLifecycleError, match="cannot be activated"):
        registry.activate("p1", "1.0.0", requested_by="alice", reason="unsafe")


def test_concurrent_activation_compare_and_swap_allows_only_one_winner():
    registry, signer = signed_registry()
    registry.publish(make("1.0.0"), signer)
    registry.publish(make("1.1.0"), signer)

    def activate(version):
        try:
            return registry.activate(
                "p1",
                version,
                requested_by="alice",
                reason="concurrent rollout",
                expected_revision=0,
            )
        except PolicyActivationConflictError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(activate, ("1.0.0", "1.1.0")))

    assert sum(isinstance(outcome, PolicyActivationConflictError) for outcome in outcomes) == 1
    assert registry.active_revision("p1") == 1


def test_activation_requires_policy_admin_when_identity_is_available():
    registry, signer = signed_registry()
    registry.publish(make(), signer)
    auditor = ClaimsIdentity(subject="auditor", roles=frozenset({Role.AUDITOR}))

    with pytest.raises(PermissionError, match="access denied"):
        registry.activate(
            "p1",
            "1.0.0",
            requested_by="auditor",
            reason="unauthorized",
            identity=auditor,
        )
