from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, replace
from typing import Any, Protocol

from ..models import GovernanceAuthorizationArtifact
from ..platform import ServicePrincipal, ServicePrincipalRegistry
from ..policy import Policy, PolicyRegistry, policy_from_dict

CONTROL_PLANE_SCHEMA = """
CREATE TABLE IF NOT EXISTS gas_tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gas_service_principals (
    principal_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    roles JSONB NOT NULL,
    allowed_actions JSONB NOT NULL,
    allowed_environments JSONB NOT NULL,
    allowed_sources JSONB NOT NULL,
    scope JSONB NOT NULL,
    public_key TEXT,
    key_status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gas_policies (
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    policy_json JSONB NOT NULL,
    published BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (policy_id, version)
);
CREATE TABLE IF NOT EXISTS gas_authorizations (
    authorization_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    request_json JSONB NOT NULL,
    context_json JSONB NOT NULL,
    mesh_inputs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    artifact_json JSONB,
    result_json JSONB,
    error_text TEXT,
    idempotency_key TEXT UNIQUE,
    request_digest TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 300,
    approvals_count INTEGER NOT NULL DEFAULT 0,
    required_approvals INTEGER NOT NULL DEFAULT 0,
    execution_attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_attempt_at DOUBLE PRECISION,
    expires_at BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gas_approval_decisions (
    approval_id BIGSERIAL PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES gas_authorizations(authorization_id) ON DELETE CASCADE,
    decision TEXT NOT NULL,
    actor_id TEXT,
    rationale TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gas_mesh_sources (
    source_id TEXT PRIMARY KEY,
    source_json JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass(frozen=True)
class TenantRecord:
    tenant_id: str
    name: str | None = None
    status: str = "active"
    created_at: float = 0.0


@dataclass(frozen=True)
class ServicePrincipalRecord:
    principal_id: str
    tenant_id: str | None = None
    roles: tuple[str, ...] = ()
    allowed_actions: tuple[str, ...] = ()
    allowed_environments: tuple[str, ...] = ()
    allowed_sources: tuple[str, ...] = ()
    scope: dict[str, Any] | None = None
    public_key: str | None = None
    key_status: str = "active"

    def to_principal(self) -> ServicePrincipal:
        return ServicePrincipal(
            principal_id=self.principal_id,
            tenant_id=self.tenant_id,
            roles=self.roles,
            allowed_actions=self.allowed_actions,
            allowed_environments=self.allowed_environments,
            allowed_sources=self.allowed_sources,
            scope=self.scope or {},
        )


@dataclass(frozen=True)
class PolicyVersionRecord:
    policy_id: str
    version: int
    policy: Policy
    published: bool = False


@dataclass(frozen=True)
class ApprovalDecisionRecord:
    authorization_id: str
    decision: str
    actor_id: str | None = None
    rationale: str | None = None
    created_at: float = 0.0


@dataclass(frozen=True)
class MeshSourceRecord:
    source_id: str
    payload: dict[str, Any]
    status: str = "active"


@dataclass(frozen=True)
class AuthorizationRecord:
    authorization_id: str
    policy_id: str
    request_payload: dict[str, Any]
    context: dict[str, Any]
    mesh_inputs: list[dict[str, Any]]
    status: str
    artifact_payload: dict[str, Any] | None = None
    result_payload: Any = None
    error_text: str | None = None
    idempotency_key: str | None = None
    request_digest: str = ""
    ttl_seconds: int = 300
    approvals_count: int = 0
    required_approvals: int = 0
    execution_attempts: int = 0
    max_attempts: int = 3
    next_attempt_at: float | None = None
    expires_at: int | None = None

    def artifact(self) -> GovernanceAuthorizationArtifact | None:
        if self.artifact_payload is None:
            return None
        return GovernanceAuthorizationArtifact.from_dict(self.artifact_payload)


class ControlPlaneRepository(Protocol):
    def create_tenant(self, tenant_id: str, *, name: str | None = None) -> TenantRecord: ...
    def list_tenants(self) -> list[TenantRecord]: ...
    def register_principal(self, principal: ServicePrincipalRecord) -> ServicePrincipalRecord: ...
    def list_principals(self) -> list[ServicePrincipalRecord]: ...
    def revoke_principal(self, principal_id: str) -> ServicePrincipalRecord: ...
    def save_policy(
        self, policy: Policy, *, version: int | None = None, published: bool = False
    ) -> PolicyVersionRecord: ...
    def list_policies(self, *, published_only: bool = False) -> list[PolicyVersionRecord]: ...
    def publish_policy(self, policy_id: str, *, version: int | None = None) -> PolicyVersionRecord: ...
    def create_authorization(
        self,
        *,
        policy_id: str,
        request_payload: dict[str, Any],
        context: dict[str, Any],
        mesh_inputs: list[dict[str, Any]],
        request_digest: str,
        idempotency_key: str | None,
        ttl_seconds: int,
        required_approvals: int,
        max_attempts: int = 3,
    ) -> AuthorizationRecord: ...
    def get_authorization(self, authorization_id: str) -> AuthorizationRecord: ...
    def get_authorization_by_idempotency_key(self, idempotency_key: str) -> AuthorizationRecord | None: ...
    def list_authorizations(self, *, status: str | None = None) -> list[AuthorizationRecord]: ...
    def list_ready_authorizations(self, *, now: float | None = None, limit: int = 10) -> list[AuthorizationRecord]: ...
    def update_authorization(self, authorization_id: str, **changes: Any) -> AuthorizationRecord: ...
    def record_approval(
        self,
        authorization_id: str,
        *,
        decision: str,
        actor_id: str | None = None,
        rationale: str | None = None,
    ) -> ApprovalDecisionRecord: ...
    def list_approvals(self, authorization_id: str) -> list[ApprovalDecisionRecord]: ...
    def save_mesh_source(self, source: MeshSourceRecord) -> MeshSourceRecord: ...


class InMemoryControlPlaneRepository:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tenants: dict[str, TenantRecord] = {}
        self._principals: dict[str, ServicePrincipalRecord] = {}
        self._policies: dict[tuple[str, int], PolicyVersionRecord] = {}
        self._authorizations: dict[str, AuthorizationRecord] = {}
        self._idempotency: dict[str, str] = {}
        self._approvals: dict[str, list[ApprovalDecisionRecord]] = {}
        self._mesh_sources: dict[str, MeshSourceRecord] = {}

    def create_tenant(self, tenant_id: str, *, name: str | None = None) -> TenantRecord:
        if not tenant_id:
            raise ValueError("tenant_id is required")
        with self._lock:
            record = TenantRecord(tenant_id=tenant_id, name=name, created_at=time.time())
            self._tenants[tenant_id] = record
            return record

    def list_tenants(self) -> list[TenantRecord]:
        return [self._tenants[key] for key in sorted(self._tenants)]

    def register_principal(self, principal: ServicePrincipalRecord) -> ServicePrincipalRecord:
        with self._lock:
            self._principals[principal.principal_id] = principal
            return principal

    def list_principals(self) -> list[ServicePrincipalRecord]:
        return [self._principals[key] for key in sorted(self._principals)]

    def revoke_principal(self, principal_id: str) -> ServicePrincipalRecord:
        with self._lock:
            current = self._principals.get(principal_id)
            if current is None:
                raise KeyError(f"unknown principal: {principal_id}")
            updated = replace(current, key_status="revoked")
            self._principals[principal_id] = updated
            return updated

    def _next_policy_version(self, policy_id: str) -> int:
        versions = [version for candidate_id, version in self._policies if candidate_id == policy_id]
        return (max(versions) + 1) if versions else 1

    def save_policy(
        self, policy: Policy, *, version: int | None = None, published: bool = False
    ) -> PolicyVersionRecord:
        with self._lock:
            effective_version = version or self._next_policy_version(policy.policy_id)
            record = PolicyVersionRecord(
                policy_id=policy.policy_id,
                version=effective_version,
                policy=policy,
                published=published,
            )
            if published:
                for key, existing in list(self._policies.items()):
                    if key[0] == policy.policy_id and existing.published:
                        self._policies[key] = replace(existing, published=False)
            self._policies[(policy.policy_id, effective_version)] = record
            return record

    def list_policies(self, *, published_only: bool = False) -> list[PolicyVersionRecord]:
        records = [self._policies[key] for key in sorted(self._policies)]
        if published_only:
            records = [record for record in records if record.published]
        return records

    def publish_policy(self, policy_id: str, *, version: int | None = None) -> PolicyVersionRecord:
        with self._lock:
            candidates = [
                record for key, record in self._policies.items() if key[0] == policy_id
            ]
            if not candidates:
                raise KeyError(f"unknown policy: {policy_id}")
            selected = max(candidates, key=lambda item: item.version) if version is None else next(
                (item for item in candidates if item.version == version),
                None,
            )
            if selected is None:
                raise KeyError(f"unknown policy version: {policy_id}:{version}")
            for key, existing in list(self._policies.items()):
                if key[0] == policy_id:
                    self._policies[key] = replace(existing, published=False)
            updated = replace(selected, published=True)
            self._policies[(updated.policy_id, updated.version)] = updated
            return updated

    def create_authorization(
        self,
        *,
        policy_id: str,
        request_payload: dict[str, Any],
        context: dict[str, Any],
        mesh_inputs: list[dict[str, Any]],
        request_digest: str,
        idempotency_key: str | None,
        ttl_seconds: int,
        required_approvals: int,
        max_attempts: int = 3,
    ) -> AuthorizationRecord:
        with self._lock:
            authorization_id = uuid.uuid4().hex
            expires_at = int(time.time()) + ttl_seconds
            record = AuthorizationRecord(
                authorization_id=authorization_id,
                policy_id=policy_id,
                request_payload=dict(request_payload),
                context=dict(context),
                mesh_inputs=list(mesh_inputs),
                status="awaiting_approval" if required_approvals > 0 else "requested",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                ttl_seconds=ttl_seconds,
                expires_at=expires_at,
                required_approvals=required_approvals,
                max_attempts=max_attempts,
            )
            self._authorizations[authorization_id] = record
            if idempotency_key is not None:
                self._idempotency[idempotency_key] = authorization_id
            return record

    def get_authorization(self, authorization_id: str) -> AuthorizationRecord:
        try:
            return self._authorizations[authorization_id]
        except KeyError as exc:
            raise KeyError(f"unknown authorization: {authorization_id}") from exc

    def get_authorization_by_idempotency_key(self, idempotency_key: str) -> AuthorizationRecord | None:
        authorization_id = self._idempotency.get(idempotency_key)
        if authorization_id is None:
            return None
        return self._authorizations[authorization_id]

    def list_authorizations(self, *, status: str | None = None) -> list[AuthorizationRecord]:
        records = [self._authorizations[key] for key in sorted(self._authorizations)]
        if status is not None:
            records = [record for record in records if record.status == status]
        return records

    def list_ready_authorizations(self, *, now: float | None = None, limit: int = 10) -> list[AuthorizationRecord]:
        effective_now = time.time() if now is None else now
        with self._lock:
            records = [
                record
                for record in self._authorizations.values()
                if record.status == "authorized"
                and (record.next_attempt_at is None or record.next_attempt_at <= effective_now)
                and (record.expires_at is None or record.expires_at > effective_now)
            ]
            records.sort(key=lambda item: (item.next_attempt_at or 0.0, item.authorization_id))
            claimed: list[AuthorizationRecord] = []
            for record in records[:limit]:
                updated = replace(record, status="executing")
                self._authorizations[record.authorization_id] = updated
                claimed.append(updated)
            return claimed

    def update_authorization(self, authorization_id: str, **changes: Any) -> AuthorizationRecord:
        with self._lock:
            current = self.get_authorization(authorization_id)
            updated = replace(current, **changes)
            self._authorizations[authorization_id] = updated
            return updated

    def record_approval(
        self,
        authorization_id: str,
        *,
        decision: str,
        actor_id: str | None = None,
        rationale: str | None = None,
    ) -> ApprovalDecisionRecord:
        with self._lock:
            _ = self.get_authorization(authorization_id)
            record = ApprovalDecisionRecord(
                authorization_id=authorization_id,
                decision=decision,
                actor_id=actor_id,
                rationale=rationale,
                created_at=time.time(),
            )
            self._approvals.setdefault(authorization_id, []).append(record)
            if decision == "approve":
                actors = {
                    item.actor_id or f"anonymous-{index}"
                    for index, item in enumerate(self._approvals[authorization_id])
                    if item.decision == "approve"
                }
                current = self.get_authorization(authorization_id)
                self._authorizations[authorization_id] = replace(
                    current,
                    approvals_count=len(actors),
                )
            return record

    def list_approvals(self, authorization_id: str) -> list[ApprovalDecisionRecord]:
        return list(self._approvals.get(authorization_id, []))

    def save_mesh_source(self, source: MeshSourceRecord) -> MeshSourceRecord:
        with self._lock:
            self._mesh_sources[source.source_id] = source
            return source


class PostgresControlPlaneRepository:
    def __init__(self, connection) -> None:
        self.connection = connection
        self._lock = threading.RLock()
        cursor = self.connection.cursor()
        try:
            cursor.execute(CONTROL_PLANE_SCHEMA)
            self.connection.commit()
        finally:
            cursor.close()

    @staticmethod
    def _dump(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _load(value: Any) -> Any:
        if value is None or isinstance(value, (dict, list)):
            return value
        return json.loads(value)

    def create_tenant(self, tenant_id: str, *, name: str | None = None) -> TenantRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gas_tenants(tenant_id, name) VALUES (%s, %s)
                ON CONFLICT (tenant_id) DO UPDATE SET name=EXCLUDED.name
                RETURNING tenant_id, name, status
                """,
                (tenant_id, name),
            )
            row = cursor.fetchone()
            self.connection.commit()
            return TenantRecord(tenant_id=row[0], name=row[1], status=row[2])
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def list_tenants(self) -> list[TenantRecord]:
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT tenant_id, name, status FROM gas_tenants ORDER BY tenant_id")
            rows = [TenantRecord(tenant_id=row[0], name=row[1], status=row[2]) for row in cursor.fetchall()]
            self.connection.commit()
            return rows
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def register_principal(self, principal: ServicePrincipalRecord) -> ServicePrincipalRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gas_service_principals(
                    principal_id, tenant_id, roles, allowed_actions, allowed_environments,
                    allowed_sources, scope, public_key, key_status
                ) VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s)
                ON CONFLICT (principal_id) DO UPDATE SET
                    tenant_id=EXCLUDED.tenant_id,
                    roles=EXCLUDED.roles,
                    allowed_actions=EXCLUDED.allowed_actions,
                    allowed_environments=EXCLUDED.allowed_environments,
                    allowed_sources=EXCLUDED.allowed_sources,
                    scope=EXCLUDED.scope,
                    public_key=EXCLUDED.public_key,
                    key_status=EXCLUDED.key_status,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    principal.principal_id,
                    principal.tenant_id,
                    self._dump(list(principal.roles)),
                    self._dump(list(principal.allowed_actions)),
                    self._dump(list(principal.allowed_environments)),
                    self._dump(list(principal.allowed_sources)),
                    self._dump(principal.scope or {}),
                    principal.public_key,
                    principal.key_status,
                ),
            )
            self.connection.commit()
            return principal
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def list_principals(self) -> list[ServicePrincipalRecord]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                SELECT principal_id, tenant_id, roles::text, allowed_actions::text,
                       allowed_environments::text, allowed_sources::text, scope::text,
                       public_key, key_status
                FROM gas_service_principals ORDER BY principal_id
                """
            )
            rows = [
                ServicePrincipalRecord(
                    principal_id=row[0],
                    tenant_id=row[1],
                    roles=tuple(self._load(row[2])),
                    allowed_actions=tuple(self._load(row[3])),
                    allowed_environments=tuple(self._load(row[4])),
                    allowed_sources=tuple(self._load(row[5])),
                    scope=self._load(row[6]),
                    public_key=row[7],
                    key_status=row[8],
                )
                for row in cursor.fetchall()
            ]
            self.connection.commit()
            return rows
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def revoke_principal(self, principal_id: str) -> ServicePrincipalRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE gas_service_principals
                SET key_status='revoked', updated_at=CURRENT_TIMESTAMP
                WHERE principal_id=%s
                RETURNING principal_id, tenant_id, roles::text, allowed_actions::text,
                          allowed_environments::text, allowed_sources::text, scope::text,
                          public_key, key_status
                """,
                (principal_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise KeyError(f"unknown principal: {principal_id}")
            self.connection.commit()
            return ServicePrincipalRecord(
                principal_id=row[0],
                tenant_id=row[1],
                roles=tuple(self._load(row[2])),
                allowed_actions=tuple(self._load(row[3])),
                allowed_environments=tuple(self._load(row[4])),
                allowed_sources=tuple(self._load(row[5])),
                scope=self._load(row[6]),
                public_key=row[7],
                key_status=row[8],
            )
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def save_policy(
        self, policy: Policy, *, version: int | None = None, published: bool = False
    ) -> PolicyVersionRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (policy.policy_id,))
            if version is None:
                cursor.execute(
                    "SELECT COALESCE(MAX(version), 0) + 1 FROM gas_policies WHERE policy_id=%s",
                    (policy.policy_id,),
                )
                version = int(cursor.fetchone()[0])
            if published:
                cursor.execute(
                    "UPDATE gas_policies SET published=FALSE, updated_at=CURRENT_TIMESTAMP WHERE policy_id=%s",
                    (policy.policy_id,),
                )
            cursor.execute(
                """
                INSERT INTO gas_policies(policy_id, version, policy_json, published)
                VALUES (%s, %s, %s::jsonb, %s)
                ON CONFLICT (policy_id, version) DO UPDATE SET
                    policy_json=EXCLUDED.policy_json,
                    published=EXCLUDED.published,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (policy.policy_id, version, self._dump(policy.to_dict()), published),
            )
            self.connection.commit()
            return PolicyVersionRecord(policy.policy_id, version, policy, published)
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def list_policies(self, *, published_only: bool = False) -> list[PolicyVersionRecord]:
        cursor = self.connection.cursor()
        try:
            sql = (
                "SELECT policy_id, version, policy_json::text, published FROM gas_policies "
                "WHERE published=TRUE ORDER BY policy_id, version"
                if published_only
                else "SELECT policy_id, version, policy_json::text, published FROM gas_policies ORDER BY policy_id, version"
            )
            cursor.execute(sql)
            rows = [
                PolicyVersionRecord(
                    policy_id=row[0],
                    version=row[1],
                    policy=policy_from_dict(self._load(row[2])),
                    published=row[3],
                )
                for row in cursor.fetchall()
            ]
            self.connection.commit()
            return rows
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def publish_policy(self, policy_id: str, *, version: int | None = None) -> PolicyVersionRecord:
        cursor = self.connection.cursor()
        try:
            if version is None:
                cursor.execute(
                    "SELECT version, policy_json::text FROM gas_policies WHERE policy_id=%s ORDER BY version DESC LIMIT 1",
                    (policy_id,),
                )
            else:
                cursor.execute(
                    "SELECT version, policy_json::text FROM gas_policies WHERE policy_id=%s AND version=%s",
                    (policy_id, version),
                )
            row = cursor.fetchone()
            if row is None:
                raise KeyError(f"unknown policy: {policy_id}")
            cursor.execute(
                "UPDATE gas_policies SET published=FALSE, updated_at=CURRENT_TIMESTAMP WHERE policy_id=%s",
                (policy_id,),
            )
            cursor.execute(
                "UPDATE gas_policies SET published=TRUE, updated_at=CURRENT_TIMESTAMP WHERE policy_id=%s AND version=%s",
                (policy_id, row[0]),
            )
            self.connection.commit()
            return PolicyVersionRecord(
                policy_id=policy_id,
                version=row[0],
                policy=policy_from_dict(self._load(row[1])),
                published=True,
            )
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def create_authorization(
        self,
        *,
        policy_id: str,
        request_payload: dict[str, Any],
        context: dict[str, Any],
        mesh_inputs: list[dict[str, Any]],
        request_digest: str,
        idempotency_key: str | None,
        ttl_seconds: int,
        required_approvals: int,
        max_attempts: int = 3,
    ) -> AuthorizationRecord:
        authorization_id = uuid.uuid4().hex
        status = "awaiting_approval" if required_approvals > 0 else "requested"
        expires_at = int(time.time()) + ttl_seconds
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gas_authorizations(
                    authorization_id, policy_id, request_json, context_json, mesh_inputs_json,
                    status, idempotency_key, request_digest, ttl_seconds, required_approvals, max_attempts, expires_at
                ) VALUES (%s, %s, %s::jsonb, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    authorization_id,
                    policy_id,
                    self._dump(request_payload),
                    self._dump(context),
                    self._dump(mesh_inputs),
                    status,
                    idempotency_key,
                    request_digest,
                    ttl_seconds,
                    required_approvals,
                    max_attempts,
                    expires_at,
                ),
            )
            self.connection.commit()
            return AuthorizationRecord(
                authorization_id=authorization_id,
                policy_id=policy_id,
                request_payload=request_payload,
                context=context,
                mesh_inputs=mesh_inputs,
                status=status,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                ttl_seconds=ttl_seconds,
                expires_at=expires_at,
                required_approvals=required_approvals,
                max_attempts=max_attempts,
            )
        except Exception:
            self.connection.rollback()
            if idempotency_key is not None:
                existing = self.get_authorization_by_idempotency_key(idempotency_key)
                if existing is not None and existing.request_digest == request_digest:
                    return existing
            raise
        finally:
            cursor.close()

    def _row_to_authorization(self, row: tuple[Any, ...]) -> AuthorizationRecord:
        return AuthorizationRecord(
            authorization_id=row[0],
            policy_id=row[1],
            request_payload=self._load(row[2]),
            context=self._load(row[3]),
            mesh_inputs=self._load(row[4]),
            status=row[5],
            artifact_payload=self._load(row[6]),
            result_payload=self._load(row[7]),
            error_text=row[8],
            idempotency_key=row[9],
            request_digest=row[10],
            ttl_seconds=row[11],
            approvals_count=row[12],
            required_approvals=row[13],
            execution_attempts=row[14],
            max_attempts=row[15],
            next_attempt_at=row[16],
            expires_at=row[17],
        )

    def get_authorization(self, authorization_id: str) -> AuthorizationRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                SELECT authorization_id, policy_id, request_json::text, context_json::text,
                       mesh_inputs_json::text, status, artifact_json::text, result_json::text,
                       error_text, idempotency_key, request_digest, ttl_seconds,
                       approvals_count, required_approvals, execution_attempts, max_attempts,
                       next_attempt_at, expires_at
                FROM gas_authorizations WHERE authorization_id=%s
                """,
                (authorization_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise KeyError(f"unknown authorization: {authorization_id}")
            record = self._row_to_authorization(row)
            self.connection.commit()
            return record
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def get_authorization_by_idempotency_key(self, idempotency_key: str) -> AuthorizationRecord | None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                SELECT authorization_id, policy_id, request_json::text, context_json::text,
                       mesh_inputs_json::text, status, artifact_json::text, result_json::text,
                       error_text, idempotency_key, request_digest, ttl_seconds,
                       approvals_count, required_approvals, execution_attempts, max_attempts,
                       next_attempt_at, expires_at
                FROM gas_authorizations WHERE idempotency_key=%s
                """,
                (idempotency_key,),
            )
            row = cursor.fetchone()
            record = None if row is None else self._row_to_authorization(row)
            self.connection.commit()
            return record
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def list_authorizations(self, *, status: str | None = None) -> list[AuthorizationRecord]:
        cursor = self.connection.cursor()
        try:
            sql = (
                """
                SELECT authorization_id, policy_id, request_json::text, context_json::text,
                       mesh_inputs_json::text, status, artifact_json::text, result_json::text,
                       error_text, idempotency_key, request_digest, ttl_seconds,
                       approvals_count, required_approvals, execution_attempts, max_attempts,
                       next_attempt_at, expires_at
                FROM gas_authorizations ORDER BY created_at, authorization_id
                """
                if status is None
                else """
                SELECT authorization_id, policy_id, request_json::text, context_json::text,
                       mesh_inputs_json::text, status, artifact_json::text, result_json::text,
                       error_text, idempotency_key, request_digest, ttl_seconds,
                       approvals_count, required_approvals, execution_attempts, max_attempts,
                       next_attempt_at, expires_at
                FROM gas_authorizations WHERE status=%s ORDER BY created_at, authorization_id
                """
            )
            cursor.execute(sql, () if status is None else (status,))
            rows = [self._row_to_authorization(row) for row in cursor.fetchall()]
            self.connection.commit()
            return rows
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def list_ready_authorizations(self, *, now: float | None = None, limit: int = 10) -> list[AuthorizationRecord]:
        effective_now = time.time() if now is None else now
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                WITH claimed AS (
                    SELECT authorization_id
                    FROM gas_authorizations
                    WHERE status='authorized'
                      AND (next_attempt_at IS NULL OR next_attempt_at <= %s)
                      AND (expires_at IS NULL OR expires_at > %s)
                    ORDER BY COALESCE(next_attempt_at, 0), authorization_id
                    LIMIT %s
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE gas_authorizations AS auth
                SET status='executing', updated_at=CURRENT_TIMESTAMP
                FROM claimed
                WHERE auth.authorization_id = claimed.authorization_id
                RETURNING auth.authorization_id, auth.policy_id, auth.request_json::text,
                          auth.context_json::text, auth.mesh_inputs_json::text, auth.status,
                          auth.artifact_json::text, auth.result_json::text, auth.error_text,
                          auth.idempotency_key, auth.request_digest, auth.ttl_seconds,
                          auth.approvals_count, auth.required_approvals, auth.execution_attempts,
                          auth.max_attempts, auth.next_attempt_at, auth.expires_at
                """,
                (effective_now, effective_now, limit),
            )
            rows = [self._row_to_authorization(row) for row in cursor.fetchall()]
            self.connection.commit()
            return rows
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def update_authorization(self, authorization_id: str, **changes: Any) -> AuthorizationRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                SELECT authorization_id, policy_id, request_json::text, context_json::text,
                       mesh_inputs_json::text, status, artifact_json::text, result_json::text,
                       error_text, idempotency_key, request_digest, ttl_seconds,
                       approvals_count, required_approvals, execution_attempts, max_attempts,
                       next_attempt_at, expires_at
                FROM gas_authorizations WHERE authorization_id=%s
                FOR UPDATE
                """,
                (authorization_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise KeyError(f"unknown authorization: {authorization_id}")
            updated = replace(self._row_to_authorization(row), **changes)
            cursor.execute(
                """
                UPDATE gas_authorizations SET
                    status=%s,
                    artifact_json=%s::jsonb,
                    result_json=%s::jsonb,
                    error_text=%s,
                    ttl_seconds=%s,
                    approvals_count=%s,
                    required_approvals=%s,
                    execution_attempts=%s,
                    max_attempts=%s,
                    next_attempt_at=%s,
                    expires_at=%s,
                    updated_at=CURRENT_TIMESTAMP
                WHERE authorization_id=%s
                """,
                (
                    updated.status,
                    self._dump(updated.artifact_payload) if updated.artifact_payload is not None else None,
                    self._dump(updated.result_payload) if updated.result_payload is not None else None,
                    updated.error_text,
                    updated.ttl_seconds,
                    updated.approvals_count,
                    updated.required_approvals,
                    updated.execution_attempts,
                    updated.max_attempts,
                    updated.next_attempt_at,
                    updated.expires_at,
                    authorization_id,
                ),
            )
            self.connection.commit()
            return updated
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def record_approval(
        self,
        authorization_id: str,
        *,
        decision: str,
        actor_id: str | None = None,
        rationale: str | None = None,
    ) -> ApprovalDecisionRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT 1 FROM gas_authorizations WHERE authorization_id=%s",
                (authorization_id,),
            )
            if cursor.fetchone() is None:
                raise KeyError(f"unknown authorization: {authorization_id}")
            cursor.execute(
                "INSERT INTO gas_approval_decisions(authorization_id, decision, actor_id, rationale) VALUES (%s, %s, %s, %s)",
                (authorization_id, decision, actor_id, rationale),
            )
            if decision == "approve":
                cursor.execute(
                    """
                    UPDATE gas_authorizations SET approvals_count=(
                        SELECT COUNT(DISTINCT COALESCE(actor_id, approval_id::text))
                        FROM gas_approval_decisions
                        WHERE authorization_id=%s AND decision='approve'
                    ), updated_at=CURRENT_TIMESTAMP
                    WHERE authorization_id=%s
                    """,
                    (authorization_id, authorization_id),
                )
            self.connection.commit()
            return ApprovalDecisionRecord(
                authorization_id=authorization_id,
                decision=decision,
                actor_id=actor_id,
                rationale=rationale,
                created_at=time.time(),
            )
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def list_approvals(self, authorization_id: str) -> list[ApprovalDecisionRecord]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT decision, actor_id, rationale, EXTRACT(EPOCH FROM created_at) FROM gas_approval_decisions WHERE authorization_id=%s ORDER BY approval_id",
                (authorization_id,),
            )
            rows = [
                ApprovalDecisionRecord(
                    authorization_id=authorization_id,
                    decision=row[0],
                    actor_id=row[1],
                    rationale=row[2],
                    created_at=float(row[3]),
                )
                for row in cursor.fetchall()
            ]
            self.connection.commit()
            return rows
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def save_mesh_source(self, source: MeshSourceRecord) -> MeshSourceRecord:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO gas_mesh_sources(source_id, source_json, status)
                VALUES (%s, %s::jsonb, %s)
                ON CONFLICT (source_id) DO UPDATE SET
                    source_json=EXCLUDED.source_json,
                    status=EXCLUDED.status,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (source.source_id, self._dump(source.payload), source.status),
            )
            self.connection.commit()
            return source
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()


def synchronize_policy_registry(
    registry: PolicyRegistry,
    repository: ControlPlaneRepository,
) -> None:
    published = repository.list_policies(published_only=True)
    if not published:
        return
    for record in published:
        registry._policies[record.policy_id] = record.policy  # noqa: SLF001
        registry._versions[record.policy_id] = record.version  # noqa: SLF001


def synchronize_principal_registry(
    registry: ServicePrincipalRegistry,
    repository: ControlPlaneRepository,
) -> None:
    registry._principals.clear()  # noqa: SLF001
    for principal in repository.list_principals():
        if principal.key_status == "revoked":
            continue
        registry.register(principal.to_principal())


def build_control_plane_repository(*, database_url: str | None = None) -> ControlPlaneRepository:
    if not database_url:
        return InMemoryControlPlaneRepository()
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("install the postgres extra to use the PostgreSQL control plane") from exc
    connection = psycopg.connect(database_url)
    return PostgresControlPlaneRepository(connection)
