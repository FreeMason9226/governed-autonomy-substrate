"""Durable SQLite identity and role-assignment store."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, Concatenate, ParamSpec, Protocol, TypeVar

from ..rbac import Role

_P = ParamSpec("_P")
_R = TypeVar("_R")

ROLE_DESCRIPTIONS = {
    Role.PLATFORM_ADMIN.value: "Full platform administration",
    Role.POLICY_ADMIN.value: "Create and manage governance policies",
    Role.OPERATOR.value: "Submit governed operations",
    Role.AUDITOR.value: "Read audit evidence",
    Role.APPROVER.value: "Approve governed policy changes",
    Role.SERVICE_PRINCIPAL.value: "Authenticated non-human principal",
}


class IdentityStoreError(RuntimeError):
    """A configured identity database failed an operation."""


class IdentityTokenReplayError(IdentityStoreError):
    """A single-use JWT identifier was already consumed."""


def _serialized(
    method: Callable[Concatenate[PostgresIdentityStore, _P], _R],
) -> Callable[Concatenate[PostgresIdentityStore, _P], _R]:
    @wraps(method)
    def wrapped(
        self: PostgresIdentityStore, *args: _P.args, **kwargs: _P.kwargs
    ) -> _R:
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapped


class IdentityStore(Protocol):
    def record_authentication(
        self,
        *,
        subject: str,
        tenant: str,
        email: str | None,
        display_name: str | None,
        issuer: str,
        roles: tuple[str, ...],
        identity_source: str,
        service_principal: bool,
        client_id: str | None = None,
    ) -> None: ...

    def assign_role(
        self, principal_id: str, role: str, assigned_by: str, *, tenant: str
    ) -> None: ...

    def roles_for(self, principal_id: str, tenant: str) -> tuple[str, ...]: ...
    def consume_token(self, issuer: str, audience: str, jti: str, expires_at: float) -> None: ...
    def role_assignments(self) -> list[dict[str, Any]]: ...
    def service_principals(self) -> list[dict[str, Any]]: ...
    def identity_events(self, *, limit: int = 100) -> list[dict[str, Any]]: ...


SQLITE_IDENTITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(subject, tenant_id)
);
CREATE TABLE IF NOT EXISTS consumed_identity_tokens (
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (issuer, audience, jti)
);
CREATE INDEX IF NOT EXISTS consumed_identity_tokens_expiry_idx
    ON consumed_identity_tokens(expires_at);
CREATE TABLE IF NOT EXISTS service_principals (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(client_id, tenant_id)
);
CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS role_assignments (
    id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(id),
    assigned_at TEXT NOT NULL,
    assigned_by TEXT NOT NULL,
    UNIQUE(principal_id, tenant_id, role_id)
);
CREATE TABLE IF NOT EXISTS identity_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    details TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS identity_events_principal_idx
    ON identity_events(principal_id, timestamp);
CREATE INDEX IF NOT EXISTS role_assignments_principal_idx
    ON role_assignments(principal_id);
"""


class SQLiteIdentityStore:
    """Persist identities, explicit role assignments, and authentication events."""

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.connection = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        self._clock = clock or _timestamp_epoch
        self.connection.executescript(SQLITE_IDENTITY_SCHEMA)
        self._seed_roles()

    def _seed_roles(self) -> None:
        with self._lock:
            self.connection.executemany(
                "INSERT OR IGNORE INTO roles(id, name, description) VALUES (?, ?, ?)",
                [
                    (role, role, description)
                    for role, description in ROLE_DESCRIPTIONS.items()
                ],
            )

    def record_authentication(
        self,
        *,
        subject: str,
        tenant: str,
        email: str | None,
        display_name: str | None,
        issuer: str,
        roles: tuple[str, ...],
        identity_source: str,
        service_principal: bool,
        client_id: str | None = None,
    ) -> None:
        if not subject or not tenant or not issuer or not identity_source:
            raise ValueError("subject, tenant, issuer, and identity source are required")
        now = _timestamp()
        details = {
            "subject": subject,
            "tenant": tenant,
            "roles": sorted(set(roles)),
            "identity_source": identity_source,
            "issuer": issuer,
            "service_principal": service_principal,
        }
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                if service_principal:
                    if client_id:
                        self.connection.execute(
                            "INSERT INTO service_principals(id, client_id, name, tenant_id, created_at) "
                            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(client_id, tenant_id) DO UPDATE SET "
                            "name=excluded.name, tenant_id=excluded.tenant_id",
                            (str(uuid.uuid4()), client_id, display_name or client_id, tenant, now),
                        )
                else:
                    self.connection.execute(
                        "INSERT INTO users(id, subject, tenant_id, email, display_name, created_at) "
                        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(subject, tenant_id) DO UPDATE SET "
                        "email=excluded.email, display_name=excluded.display_name",
                        (str(uuid.uuid4()), subject, tenant, email, display_name, now),
                    )
                self.connection.execute(
                    "INSERT INTO identity_events(id, event_type, principal_id, details, timestamp) "
                    "VALUES (?, 'authenticated', ?, ?, ?)",
                    (str(uuid.uuid4()), subject, json.dumps(details, sort_keys=True), now),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def assign_role(
        self,
        principal_id: str,
        role: str,
        assigned_by: str,
        *,
        tenant: str,
    ) -> None:
        if not principal_id or not assigned_by or not tenant:
            raise ValueError("principal_id, tenant, and assigned_by are required")
        try:
            role_value = Role(role).value
        except ValueError as exc:
            raise ValueError(f"unknown GAS role: {role}") from exc
        assignment_id, now = str(uuid.uuid4()), _timestamp()
        details = {
            "subject": principal_id,
            "tenant": tenant,
            "roles": [role_value],
            "identity_source": "role_assignment",
            "assigned_by": assigned_by,
        }
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute(
                    "INSERT INTO role_assignments"
                    "(id, principal_id, tenant_id, role_id, assigned_at, assigned_by) "
                    "VALUES (?, ?, ?, ?, ?, ?) "
                    "ON CONFLICT(principal_id, tenant_id, role_id) DO NOTHING",
                    (assignment_id, principal_id, tenant, role_value, now, assigned_by),
                )
                self.connection.execute(
                    "INSERT INTO identity_events(id, event_type, principal_id, details, timestamp) "
                    "VALUES (?, 'role_assigned', ?, ?, ?)",
                    (str(uuid.uuid4()), principal_id, json.dumps(details, sort_keys=True), now),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def roles_for(self, principal_id: str, tenant: str) -> tuple[str, ...]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT role_id FROM role_assignments "
                "WHERE principal_id=? AND tenant_id=? ORDER BY role_id",
                (principal_id, tenant),
            ).fetchall()
        return tuple(row["role_id"] for row in rows)

    def consume_token(self, issuer: str, audience: str, jti: str, expires_at: float) -> None:
        now = self._clock()
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute(
                    "DELETE FROM consumed_identity_tokens WHERE expires_at<=?", (now,)
                )
                self.connection.execute(
                    "INSERT INTO consumed_identity_tokens(issuer, audience, jti, expires_at) "
                    "VALUES (?, ?, ?, ?)",
                    (issuer, audience, jti, expires_at),
                )
                self.connection.commit()
            except sqlite3.IntegrityError as exc:
                self.connection.rollback()
                raise IdentityTokenReplayError("JWT token replay detected") from exc
            except Exception:
                self.connection.rollback()
                raise

    def role_assignments(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT id, principal_id, tenant_id AS tenant, role_id AS role, assigned_at, assigned_by "
                "FROM role_assignments ORDER BY assigned_at, id"
            ).fetchall()
        return [dict(row) for row in rows]

    def service_principals(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT id, client_id, name, tenant_id, created_at "
                "FROM service_principals ORDER BY tenant_id, client_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def identity_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._lock:
            rows = self.connection.execute(
                "SELECT id, event_type, principal_id, details, timestamp "
                "FROM identity_events ORDER BY timestamp DESC, id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                **dict(row),
                "details": json.loads(row["details"]),
            }
            for row in rows
        ]

    def close(self) -> None:
        self.connection.close()


class PostgresIdentityStore:
    """PostgreSQL adapter; apply deploy/postgres/migrations/002_identity_schema.sql first."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self._lock = threading.RLock()

    @_serialized
    def record_authentication(
        self,
        *,
        subject: str,
        tenant: str,
        email: str | None,
        display_name: str | None,
        issuer: str,
        roles: tuple[str, ...],
        identity_source: str,
        service_principal: bool,
        client_id: str | None = None,
    ) -> None:
        if not subject or not tenant or not issuer or not identity_source:
            raise ValueError("subject, tenant, issuer, and identity source are required")
        details = json.dumps(
            {
                "subject": subject,
                "tenant": tenant,
                "roles": sorted(set(roles)),
                "identity_source": identity_source,
                "issuer": issuer,
                "service_principal": service_principal,
            },
            sort_keys=True,
        )
        cursor = self.connection.cursor()
        try:
            if service_principal:
                if client_id:
                    cursor.execute(
                        "INSERT INTO service_principals(id, client_id, name, tenant_id) "
                        "VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT(client_id, tenant_id) DO UPDATE SET "
                        "name=EXCLUDED.name, tenant_id=EXCLUDED.tenant_id",
                        (str(uuid.uuid4()), client_id, display_name or client_id, tenant),
                    )
            else:
                cursor.execute(
                    "INSERT INTO users(subject, tenant_id, email, display_name) "
                    "VALUES (%s, %s, %s, %s) ON CONFLICT(subject, tenant_id) DO UPDATE SET "
                    "email=EXCLUDED.email, display_name=EXCLUDED.display_name",
                    (subject, tenant, email, display_name),
                )
            cursor.execute(
                "INSERT INTO identity_events(event_type, principal_id, details) "
                "VALUES ('authenticated', %s, %s::jsonb)",
                (subject, details),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    @_serialized
    def assign_role(
        self,
        principal_id: str,
        role: str,
        assigned_by: str,
        *,
        tenant: str,
    ) -> None:
        if not principal_id or not assigned_by or not tenant:
            raise ValueError("principal_id, tenant, and assigned_by are required")
        try:
            role_value = Role(role).value
        except ValueError as exc:
            raise ValueError(f"unknown GAS role: {role}") from exc
        details = json.dumps(
            {
                "subject": principal_id,
                "tenant": tenant,
                "roles": [role_value],
                "identity_source": "role_assignment",
                "assigned_by": assigned_by,
            },
            sort_keys=True,
        )
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO role_assignments(principal_id, tenant_id, role_id, assigned_by) "
                "VALUES (%s, %s, %s, %s) "
                "ON CONFLICT(principal_id, tenant_id, role_id) DO NOTHING",
                (principal_id, tenant, role_value, assigned_by),
            )
            cursor.execute(
                "INSERT INTO identity_events(event_type, principal_id, details) "
                "VALUES ('role_assigned', %s, %s::jsonb)",
                (principal_id, details),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    @_serialized
    def roles_for(self, principal_id: str, tenant: str) -> tuple[str, ...]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT role_id FROM role_assignments "
                "WHERE principal_id=%s AND tenant_id=%s ORDER BY role_id",
                (principal_id, tenant),
            )
            return tuple(row[0] for row in cursor.fetchall())
        finally:
            cursor.close()

    @_serialized
    def role_assignments(self) -> list[dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT id::text, principal_id, tenant_id AS tenant, role_id AS role, "
                "assigned_at, assigned_by "
                "FROM role_assignments ORDER BY assigned_at, id"
            )
            rows = cursor.fetchall()
            return [
                dict(
                    zip(
                        ("id", "principal_id", "tenant", "role", "assigned_at", "assigned_by"),
                        row,
                        strict=True,
                    )
                )
                for row in rows
            ]
        finally:
            cursor.close()

    @_serialized
    def service_principals(self) -> list[dict[str, Any]]:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT id, client_id, name, tenant_id, created_at "
                "FROM service_principals ORDER BY tenant_id, client_id"
            )
            rows = cursor.fetchall()
            keys = ("id", "client_id", "name", "tenant_id", "created_at")
            return [dict(zip(keys, row, strict=True)) for row in rows]
        finally:
            cursor.close()

    @_serialized
    def identity_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT id::text, event_type, principal_id, details, timestamp "
                "FROM identity_events ORDER BY timestamp DESC, id DESC LIMIT %s",
                (limit,),
            )
            rows = cursor.fetchall()
            result = []
            for event_id, event_type, principal_id, details, timestamp in rows:
                if isinstance(details, str):
                    details = json.loads(details)
                result.append(
                    {
                        "id": event_id,
                        "event_type": event_type,
                        "principal_id": principal_id,
                        "details": details,
                        "timestamp": timestamp,
                    }
                )
            return result
        finally:
            cursor.close()


    @_serialized
    def consume_token(self, issuer: str, audience: str, jti: str, expires_at: float) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "DELETE FROM consumed_identity_tokens WHERE expires_at<=CURRENT_TIMESTAMP"
            )
            cursor.execute(
                "INSERT INTO consumed_identity_tokens(issuer, audience, jti, expires_at) "
                "VALUES (%s, %s, %s, to_timestamp(%s)) ON CONFLICT DO NOTHING "
                "RETURNING jti",
                (issuer, audience, jti, expires_at),
            )
            if cursor.fetchone() is None:
                self.connection.rollback()
                raise IdentityTokenReplayError("JWT token replay detected")
            self.connection.commit()
        except IdentityStoreError:
            raise
        except Exception as exc:
            self.connection.rollback()
            raise IdentityStoreError("JWT replay store is unavailable") from exc
        finally:
            cursor.close()


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _timestamp_epoch() -> float:
    return datetime.now(UTC).timestamp()
