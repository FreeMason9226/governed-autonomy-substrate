import pytest

from governed_autonomy import Policy, PolicyRegistry


def test_registry_exposes_stable_policy_digests():
    policy = Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {})
    registry = PolicyRegistry((policy,))

    assert registry.get("files-v1") == policy
    assert registry.digests() == {"files-v1": policy.digest()}


def test_registry_rejects_policy_id_reuse_with_different_contents():
    registry = PolicyRegistry(
        (Policy("files-v1", ("write_file",), {"write_file": ("path",)}, {}),)
    )
    changed = Policy(
        "files-v1",
        ("write_file",),
        {"write_file": ("path", "content")},
        {},
    )

    with pytest.raises(ValueError, match="already registered"):
        registry.register(changed)
