import pytest

from governed_autonomy.rbac import ClaimsMapper, Role, require_roles


def test_maps_roles_scopes_and_groups_and_ignores_unknown():
    mapper = ClaimsMapper({"ops-team": Role.OPERATOR})
    ident = mapper.map_to_identity(
        {"sub": "u1", "tid": "t1", "azp": "svc", "roles": ["auditor", "junk"], "groups": ["ops-team"]}
    )
    assert ident.roles == {Role.AUDITOR, Role.OPERATOR}
    assert ident.tenant_id == "t1" and ident.service_id == "svc"


def test_legacy_admin_role_and_scope_map_to_operator():
    mapper = ClaimsMapper()
    assert Role.OPERATOR in mapper.map_to_identity({"sub": "a", "roles": ["gas-admin"]}).roles
    assert Role.OPERATOR in mapper.map_to_identity({"sub": "a", "scope": "x gas.admin"}).roles


def test_missing_subject_rejected():
    with pytest.raises(ValueError):
        ClaimsMapper().map_to_identity({"roles": ["operator"]})


def test_require_roles():
    mapper = ClaimsMapper()
    auditor = mapper.map_to_identity({"sub": "a", "roles": ["auditor"]})
    admin = mapper.map_to_identity({"sub": "b", "roles": ["platform_admin"]})
    require_roles(auditor, [Role.AUDITOR])
    require_roles(admin, [Role.OPERATOR])
    with pytest.raises(PermissionError):
        require_roles(auditor, [Role.OPERATOR])
