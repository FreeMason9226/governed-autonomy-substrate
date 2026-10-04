"""Claims-to-role mapping and role checks for OIDC-authenticated operators."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Role(StrEnum):
    PLATFORM_ADMIN = "platform_admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"


@dataclass(frozen=True)
class ClaimsIdentity:
    subject: str
    tenant_id: str | None = None
    service_id: str | None = None
    email: str | None = None
    roles: frozenset[Role] = frozenset()
    groups: tuple[str, ...] = ()


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return value.split()
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, str)]
    return []


class ClaimsMapper:
    """Maps IdP roles, groups and scopes onto GAS roles. Unknown values grant nothing."""

    def __init__(
        self,
        role_mapping: Mapping[str, Role] | None = None,
        *,
        legacy_admin_role: str = "gas-admin",
        legacy_admin_scope: str = "gas.admin",
    ) -> None:
        self.role_mapping = dict(role_mapping or {})
        self.role_mapping.setdefault(legacy_admin_role, Role.OPERATOR)
        self.role_mapping.setdefault(legacy_admin_scope, Role.OPERATOR)

    def map_to_identity(self, claims: Mapping[str, Any]) -> ClaimsIdentity:
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise ValueError("claims are missing sub")
        groups = _as_list(claims.get("groups"))
        candidates = [
            *_as_list(claims.get("roles")),
            *_as_list(claims.get("scope")),
            *_as_list(claims.get("scp")),
            *groups,
        ]
        roles: set[Role] = set()
        for item in candidates:
            if item in self.role_mapping:
                roles.add(self.role_mapping[item])
            else:
                try:
                    roles.add(Role(item))
                except ValueError:
                    continue
        service = claims.get("appid") or claims.get("azp") or claims.get("client_id")
        email = claims.get("email") or claims.get("upn")
        tenant = claims.get("tid") or claims.get("tenant_id")
        return ClaimsIdentity(
            subject=subject,
            tenant_id=tenant if isinstance(tenant, str) else None,
            service_id=service if isinstance(service, str) else None,
            email=email if isinstance(email, str) else None,
            roles=frozenset(roles),
            groups=tuple(groups),
        )


def require_roles(identity: ClaimsIdentity, required: Iterable[Role]) -> None:
    """Raise PermissionError unless the identity holds a required role or is a platform admin."""
    needed = set(required)
    if Role.PLATFORM_ADMIN in identity.roles or identity.roles & needed:
        return
    raise PermissionError(f"access denied; required roles: {sorted(r.value for r in needed)}")

