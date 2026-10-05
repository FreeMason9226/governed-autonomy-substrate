import pytest

from governed_autonomy.rbac import ClaimsMapper, Role, authorize, has_permission, require_roles


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


def test_maps_enterprise_app_role_names_case_insensitively():
    identity = ClaimsMapper().map_to_identity(
        {
            "sub": "enterprise-user",
            "roles": ["PlatformAdmin", "PolicyAdmin", "Approver", "Auditor", "Operator"],
        }
    )

    assert identity.roles == {
        Role.PLATFORM_ADMIN,
        Role.POLICY_ADMIN,
        Role.APPROVER,
        Role.AUDITOR,
        Role.OPERATOR,
    }


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


def test_authorization_decorator_requires_identity_and_permission_evaluation():
    @authorize(Role.OPERATOR)
    def run_governed_action(*, identity, action):
        return action

    operator = ClaimsMapper().map_to_identity({"sub": "operator", "roles": ["operator"]})
    auditor = ClaimsMapper().map_to_identity({"sub": "auditor", "roles": ["auditor"]})
    assert has_permission(operator, [Role.OPERATOR])
    assert run_governed_action(identity=operator, action="write") == "write"
    with pytest.raises(PermissionError):
        run_governed_action(identity=auditor, action="write")
    with pytest.raises(PermissionError):
        run_governed_action(action="write")
