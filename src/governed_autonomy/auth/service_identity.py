"""Authenticated workload, machine, service-principal and managed identities."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ServiceIdentity:
    subject: str
    tenant: str | None
    issuer: str
    identity_type: str
    client_id: str | None = None

    def __post_init__(self) -> None:
        if not self.subject or not self.issuer:
            raise ValueError("service identity subject and issuer are required")
        if self.identity_type not in {
            "service_principal",
            "managed_identity",
            "workload_identity",
            "machine",
        }:
            raise ValueError("unsupported service identity type")


def service_identity_from_claims(claims: Mapping[str, Any], issuer: str) -> ServiceIdentity:
    subject = claims.get("oid") or claims.get("sub")
    if not isinstance(subject, str) or not subject:
        raise ValueError("service identity claims require oid or sub")
    client_id = claims.get("azp") or claims.get("appid") or claims.get("client_id")
    client_id = client_id if isinstance(client_id, str) else None
    tenant = claims.get("tid")
    tenant = tenant if isinstance(tenant, str) else None
    idtyp = claims.get("idtyp")
    if claims.get("xms_mirid"):
        identity_type = "managed_identity"
    elif claims.get("workload_identity") or claims.get("workload"):
        identity_type = "workload_identity"
    elif idtyp == "app":
        identity_type = "service_principal"
    else:
        identity_type = "machine"
    return ServiceIdentity(subject, tenant, issuer, identity_type, client_id)
