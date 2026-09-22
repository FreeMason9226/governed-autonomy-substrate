import pytest

from governed_autonomy import Policy


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"allowed_actions": ("",)}, "allowed_actions"),
        ({"allowed_actions": ("z", "a")}, "sorted"),
        ({"required_context": ("tenant_id", "actor_id")}, "sorted"),
        ({"required_fields": {"write": ("path", 1)}}, "required_fields"),
        ({"exact_context": []}, "exact_context"),
    ],
)
def test_invalid_policy_definitions_fail_closed(kwargs, message):
    values = {
        "policy_id": "files-v1",
        "allowed_actions": ("write",),
        "required_fields": {},
        "exact_fields": {},
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=message):
        Policy(**values)
