import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Protocol
from urllib.parse import parse_qs, quote, urlencode, urlsplit

from .admin_ui import render_admin_css, render_admin_js, render_admin_ui
from .auth.store import IdentityStore, PostgresIdentityStore, SQLiteIdentityStore
from .bootstrap import build_runtime_service
from .deployment import (
    BoundedRateLimiter,
    PostgresRateLimiter,
    RateLimiter,
    TLSConfig,
    security_headers,
)
from .errors import AuthorizationError
from .health import health_report
from .identity import (
    EntraOIDCConfig,
    ExternalIdentity,
    IdentityValidationError,
    OIDCAuthCodeClient,
    OIDCValidator,
    UrlJWKSProvider,
    discover_oidc_configuration,
    entra_oidc_validator_from_discovery,
    oidc_validator_from_discovery,
)
from .issuer import PolicyDeniedError
from .jobs import JobStoreError, JobSubmissionStore, SQLiteJobStore
from .logging_config import configure_logging
from .mesh import GovernanceInput
from .observability import TraceContext, TraceRecorder
from .operator_auth import OperatorKeyStore
from .platform import RuntimeIdentity
from .platform_admin import PolicyChangeManager, TrustChangeManager
from .policy import policy_from_dict
from .policy_registry import (
    PolicySigner,
    StoredPolicy,
    VersionedPolicyRegistry,
)
from .rbac import Role
from .service import GovernedService

API_VERSION = "1"
_VERSIONED_GET = frozenset({"/health", "/livez", "/readyz", "/startupz", "/audit", "/openapi.json"})


def _unversioned(route: str) -> str:
    """Map /api/v1/<read-only endpoint> onto its canonical route."""
    if route.startswith("/api/v1/"):
        stripped = route[len("/api/v1") :]
        if stripped in _VERSIONED_GET:
            return stripped
    return route


access_log = logging.getLogger("governed_autonomy.access")
_OIDC_SESSION_COOKIE = "__Host-gas-session"
_OIDC_STATE_COOKIE = "__Host-gas-login"
_LOGIN_STATE_TTL_SECONDS = 600
_MAX_BROWSER_SESSION_SECONDS = 8 * 60 * 60


@dataclass(frozen=True)
class _PendingOIDCLogin:
    nonce: str
    code_verifier: str
    expires_at: float
    next_path: str


@dataclass(frozen=True)
class _BrowserSession:
    identity: RuntimeIdentity
    expires_at: float


class OIDCSessionRepository(Protocol):
    """Shared storage for one-time OIDC state and browser sessions."""

    def save_pending(self, state: str, pending: _PendingOIDCLogin) -> None: ...
    def consume_pending(self, state: str, now: float) -> _PendingOIDCLogin | None: ...
    def save_session(self, token: str, session: _BrowserSession) -> None: ...
    def get_session(self, token: str, now: float) -> _BrowserSession | None: ...
    def revoke_session(self, token: str) -> None: ...


class PostgresOIDCSessionRepository:
    """PostgreSQL session store for horizontally scaled OIDC browser sign-in."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS gas_oidc_sessions (
                    token_hash TEXT PRIMARY KEY,
                    record_type TEXT NOT NULL CHECK (record_type IN ('pending', 'session')),
                    payload JSONB NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS gas_oidc_sessions_expiry_idx "
                "ON gas_oidc_sessions(expires_at)"
            )
            self.connection.commit()
        finally:
            cursor.close()

    @staticmethod
    def _key(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def save_pending(self, state: str, pending: _PendingOIDCLogin) -> None:
        self._save(
            state,
            "pending",
            {
                "nonce": pending.nonce,
                "code_verifier": pending.code_verifier,
                "next_path": pending.next_path,
            },
            pending.expires_at,
        )

    def consume_pending(self, state: str, now: float) -> _PendingOIDCLogin | None:
        payload = self._consume(state, "pending", now)
        if payload is None:
            return None
        return _PendingOIDCLogin(
            nonce=str(payload["nonce"]),
            code_verifier=str(payload["code_verifier"]),
            expires_at=now + 1,
            next_path=str(payload["next_path"]),
        )

    def save_session(self, token: str, session: _BrowserSession) -> None:
        self._save(token, "session", asdict(session.identity), session.expires_at)

    def get_session(self, token: str, now: float) -> _BrowserSession | None:
        payload = self._get(token, "session", now)
        if payload is None:
            return None
        payload["roles"] = tuple(payload.get("roles", ()))
        payload["groups"] = tuple(payload.get("groups", ()))
        payload["scope"] = dict(payload.get("scope", {}))
        return _BrowserSession(identity=RuntimeIdentity(**payload), expires_at=now + 1)

    def revoke_session(self, token: str) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "DELETE FROM gas_oidc_sessions WHERE token_hash=%s AND record_type='session'",
                (self._key(token),),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def _save(
        self, token: str, record_type: str, payload: dict[str, Any], expires_at: float
    ) -> None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "INSERT INTO gas_oidc_sessions(token_hash, record_type, payload, expires_at) "
                "VALUES (%s, %s, %s::jsonb, to_timestamp(%s)) "
                "ON CONFLICT(token_hash) DO UPDATE SET record_type=EXCLUDED.record_type, "
                "payload=EXCLUDED.payload, expires_at=EXCLUDED.expires_at",
                (self._key(token), record_type, json.dumps(payload), expires_at),
            )
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()

    def _get(self, token: str, record_type: str, now: float) -> dict[str, Any] | None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "SELECT payload FROM gas_oidc_sessions "
                "WHERE token_hash=%s AND record_type=%s AND expires_at > to_timestamp(%s)",
                (self._key(token), record_type, now),
            )
            row = cursor.fetchone()
            return dict(row[0]) if row is not None else None
        finally:
            cursor.close()

    def _consume(self, token: str, record_type: str, now: float) -> dict[str, Any] | None:
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                "DELETE FROM gas_oidc_sessions "
                "WHERE token_hash=%s AND record_type=%s AND expires_at > to_timestamp(%s) "
                "RETURNING payload",
                (self._key(token), record_type, now),
            )
            row = cursor.fetchone()
            self.connection.commit()
            return dict(row[0]) if row is not None else None
        except Exception:
            self.connection.rollback()
            raise
        finally:
            cursor.close()


class _OIDCSessionStore:
    """Process-local, bounded, single-use OAuth state and browser sessions."""

    def __init__(
        self,
        *,
        clock: Any = time.time,
        max_entries: int = 10_000,
        repository: OIDCSessionRepository | None = None,
    ) -> None:
        self._clock = clock
        self._max_entries = max_entries
        self._lock = threading.RLock()
        self._pending: dict[str, _PendingOIDCLogin] = {}
        self._sessions: dict[str, _BrowserSession] = {}
        self._repository = repository

    def begin_login(self, *, next_path: str) -> tuple[str, str, str]:
        now = self._clock()
        with self._lock:
            self._prune(now)
            if len(self._pending) + len(self._sessions) >= self._max_entries:
                raise IdentityValidationError("OIDC session capacity is exhausted")
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            verifier = secrets.token_urlsafe(48)
            self._pending[state] = _PendingOIDCLogin(
                nonce=nonce,
                code_verifier=verifier,
                expires_at=now + _LOGIN_STATE_TTL_SECONDS,
                next_path=next_path,
            )
            if self._repository is not None:
                self._repository.save_pending(state, self._pending.pop(state))
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
            return state, nonce, challenge.rstrip(b"=").decode("ascii")

    def consume_login(self, state: str) -> _PendingOIDCLogin:
        now = self._clock()
        with self._lock:
            self._prune(now)
            pending = (
                self._repository.consume_pending(state, now)
                if self._repository is not None
                else self._pending.pop(state, None)
            )
            if pending is None or now >= pending.expires_at:
                raise IdentityValidationError("OIDC login state is invalid or expired")
            return pending

    def create_session(self, identity: ExternalIdentity) -> tuple[str, int]:
        now = self._clock()
        token_expiry = identity.claims.get("exp")
        if (
            not isinstance(token_expiry, (int, float))
            or isinstance(token_expiry, bool)
            or token_expiry <= now
        ):
            raise IdentityValidationError("OIDC identity token expiry is invalid")
        expires_at = min(float(token_expiry), now + _MAX_BROWSER_SESSION_SECONDS)
        core_identity = RuntimeIdentity.from_external_identity(identity)
        session_token = secrets.token_urlsafe(32)
        with self._lock:
            self._prune(now)
            if len(self._pending) + len(self._sessions) >= self._max_entries:
                raise IdentityValidationError("OIDC session capacity is exhausted")
            session = _BrowserSession(
                identity=core_identity,
                expires_at=expires_at,
            )
            if self._repository is not None:
                self._repository.save_session(session_token, session)
            else:
                self._sessions[self._session_key(session_token)] = session
        return session_token, max(1, int(expires_at - now))

    def get_session(self, session_token: str) -> RuntimeIdentity | None:
        now = self._clock()
        key = self._session_key(session_token)
        with self._lock:
            if self._repository is not None:
                return self._repository.get_session(session_token, now)
            session = self._sessions.get(key)
            if session is None:
                return None
            if now >= session.expires_at:
                self._sessions.pop(key, None)
                return None
            return session.identity

    def revoke_session(self, session_token: str) -> None:
        with self._lock:
            if self._repository is not None:
                self._repository.revoke_session(session_token)
            else:
                self._sessions.pop(self._session_key(session_token), None)

    def _prune(self, now: float) -> None:
        self._pending = {
            state: login for state, login in self._pending.items() if now < login.expires_at
        }
        self._sessions = {
            key: session for key, session in self._sessions.items() if now < session.expires_at
        }

    @staticmethod
    def _session_key(session_token: str) -> str:
        return hashlib.sha256(session_token.encode("utf-8")).hexdigest()


class AuthenticatedAPI:
    def __init__(
        self,
        service: GovernedService,
        *,
        bearer_token: str | None = None,
        oidc_validator: OIDCValidator | None = None,
        oidc_only: bool = False,
        oidc_auth_client: OIDCAuthCodeClient | None = None,
        oidc_login_validator: OIDCValidator | None = None,
        oidc_cookie_secure: bool = True,
        oidc_session_repository: OIDCSessionRepository | None = None,
        operator_token: str | None = None,
        operator_role: str = "gas-admin",
        operator_key_store: OperatorKeyStore | None = None,
        identity_store: IdentityStore | None = None,
        job_store: JobSubmissionStore | None = None,
        versioned_policy_registry: VersionedPolicyRegistry | None = None,
        policy_registry_signer: PolicySigner | None = None,
        max_body_bytes: int = 64 * 1024,
        rate_limit: int = 120,
        rate_limiter: RateLimiter | None = None,
        tracer: TraceRecorder | None = None,
        cors_origins: Sequence[str] = (),
    ) -> None:
        if not bearer_token and oidc_validator is None:
            raise ValueError("bearer_token or oidc_validator is required")
        if oidc_only and oidc_validator is None:
            raise ValueError("oidc_validator is required when oidc_only is enabled")
        if oidc_auth_client is not None and oidc_validator is None:
            raise ValueError("oidc_validator is required for browser sign-in")
        if oidc_auth_client is not None and oidc_login_validator is None:
            oidc_login_validator = oidc_validator
        if max_body_bytes <= 0:
            raise ValueError("positive max_body_bytes is required")
        self.service = service
        self.bearer_token = bearer_token
        self.oidc_validator = oidc_validator
        self.oidc_only = oidc_only
        self.oidc_auth_client = oidc_auth_client
        self.oidc_login_validator = oidc_login_validator
        self.oidc_cookie_secure = oidc_cookie_secure
        self.oidc_sessions = (
            _OIDCSessionStore(repository=oidc_session_repository)
            if oidc_auth_client is not None
            else None
        )
        self.operator_token = operator_token
        self.operator_role = operator_role
        self.operator_key_store = operator_key_store
        self.identity_store = identity_store
        self.job_store = job_store
        self.versioned_policy_registry = versioned_policy_registry
        self.policy_registry_signer = policy_registry_signer
        self.max_body_bytes = max_body_bytes
        self.cors_origins = frozenset(o.rstrip("/") for o in cors_origins if o)
        self.rate_limiter = rate_limiter or BoundedRateLimiter(rate_limit)
        self.tracer = tracer
        if (
            self.service.policy_change_manager is not None
            and self.service.policy_change_manager.actor_audit_hook is None
        ):
            self.service.policy_change_manager.actor_audit_hook = (
                lambda event, subject_id, actor_id: self.service.record_governance_event(
                    event, subject_id, actor_id=actor_id
                )
            )
        if (
            self.service.trust_change_manager is not None
            and self.service.trust_change_manager.actor_audit_hook is None
        ):
            self.service.trust_change_manager.actor_audit_hook = (
                lambda event, subject_id, actor_id: self.service.record_governance_event(
                    event, subject_id, actor_id=actor_id
                )
            )

    def handler(self) -> type[BaseHTTPRequestHandler]:
        api = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "GovernedAutonomy/0.2"

            def log_message(self, format: str, *args: Any) -> None:
                # Structured access log; never logs headers or bodies.
                if not args or not isinstance(args[1] if len(args) > 1 else None, (str, int)):
                    return
                access_log.info(
                    "request",
                    extra={
                        "method": self.command,
                        "path": urlsplit(self.path).path,
                        "status": str(args[1]),
                        "request_id": getattr(self, "_rid", None),
                        "client": self.client_address[0],
                    },
                )

            def _cors_headers(self) -> dict[str, str]:
                requested = (self.headers.get("Origin") or "").rstrip("/")
                if not re.fullmatch(r"[A-Za-z0-9.:/_-]{1,255}", requested):
                    return {}
                origin = next((o for o in api.cors_origins if o == requested), None)
                if not origin:
                    return {}
                return {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Expose-Headers": "X-Request-ID, traceparent",
                    "Vary": "Origin",
                }

            def _send_cors(self) -> None:
                for k, v in self._cors_headers().items():
                    if "\r" not in v and "\n" not in v:
                        self.send_header(k, v)

            def do_OPTIONS(self) -> None:
                cors = self._cors_headers()
                self.send_response(HTTPStatus.NO_CONTENT if cors else HTTPStatus.FORBIDDEN)
                for k, v in cors.items():
                    self.send_header(k, v)
                if cors:
                    self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                    self.send_header(
                        "Access-Control-Allow-Headers", "Authorization, Content-Type, traceparent"
                    )
                    self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                route = _unversioned(urlsplit(self.path).path)
                if not api._allowed(self):
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
                    return
                if route == "/auth/login":
                    api._handle_oidc_login(self)
                    return
                if route == "/auth/callback":
                    api._handle_oidc_callback(self)
                    return
                try:
                    authenticated = api._authenticated(self)
                except sqlite3.Error:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "authentication backend unavailable"},
                    )
                    return
                if not authenticated:
                    if (
                        api.oidc_auth_client is not None
                        and route.startswith("/admin")
                        and not self.headers.get("Authorization")
                    ):
                        next_path = urlencode({"next": self.path})
                        self.send_response(HTTPStatus.FOUND)
                        self.send_header("Location", f"/auth/login?{next_path}")
                        self.send_header("Cache-Control", "no-store")
                        for key, value in security_headers().items():
                            self.send_header(key, value)
                        self.end_headers()
                        return
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                if route == "/auth/me":
                    identity = getattr(self, "gas_runtime_identity", None)
                    if identity is None:
                        self._send(
                            HTTPStatus.UNAUTHORIZED,
                            {"error": "authenticated identity required"},
                        )
                    else:
                        self._send(HTTPStatus.OK, identity.to_identity_dict())
                    return
                if route.startswith("/admin") and not api._admin_authorized(
                    self, method="GET", route=route
                ):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "role authorization required"},
                    )
                    return
                if not api._api_authorized(self, method="GET", route=route):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "role authorization required"},
                    )
                    return
                if route == "/admin":
                    self._send_static(render_admin_ui(), "text/html; charset=utf-8")
                    return
                if route == "/admin/app.js":
                    self._send_static(render_admin_js(), "text/javascript; charset=utf-8")
                    return
                if route == "/admin/app.css":
                    self._send_static(render_admin_css(), "text/css; charset=utf-8")
                    return
                if route in {"/health", "/livez", "/readyz", "/startupz"}:
                    report = health_report(
                        replay_log=api.service.boundary.replay_log,
                        trust_store=api.service.boundary.trust_store,
                        policy_registry=api.service.policies,
                        mesh_source_registry=api.service.mesh_source_registry,
                    )
                    if route == "/livez":
                        report = {"ok": True, "status": "live"}
                    elif route == "/startupz":
                        report = {"ok": True, "status": "started"}
                    elif route == "/readyz" and not report["ok"]:
                        self._send(HTTPStatus.SERVICE_UNAVAILABLE, report)
                        return
                    self._send(HTTPStatus.OK, report)
                    return
                if route == "/audit":
                    self._send(HTTPStatus.OK, api.service.audit_report())
                    return
                if route == "/admin/policies":
                    self._send(HTTPStatus.OK, {"policies": api.service.policies.to_dict()})
                    return
                if route.startswith("/admin/policy-registry/"):
                    self._handle_policy_registry_get(route)
                    return
                if route == "/admin/proposals":
                    self._send(HTTPStatus.OK, api.list_proposals())
                    return
                if route == "/admin/trust":
                    self._send(HTTPStatus.OK, api.trust_snapshot())
                    return
                if route == "/admin/operator-keys":
                    if api.operator_key_store is None:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "operator API key management is not configured"},
                        )
                        return
                    try:
                        self._send(HTTPStatus.OK, api.list_operator_keys())
                    except sqlite3.Error:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "operator key store unavailable"},
                        )
                    return
                if route == "/admin/identities/role-assignments":
                    if api.identity_store is None:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "identity store is not configured"},
                        )
                    else:
                        self._send(
                            HTTPStatus.OK,
                            {"assignments": api.identity_store.role_assignments()},
                        )
                    return
                if route == "/admin/identities/service-principals":
                    if api.identity_store is None:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "identity store is not configured"},
                        )
                    else:
                        self._send(
                            HTTPStatus.OK,
                            {"service_principals": api.identity_store.service_principals()},
                        )
                    return
                if route == "/admin/identities/events":
                    if api.identity_store is None:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "identity store is not configured"},
                        )
                    else:
                        self._send(
                            HTTPStatus.OK,
                            {"events": api.identity_store.identity_events()},
                        )
                    return
                if route.startswith("/admin/jobs/"):
                    self._handle_admin_job_get(route)
                    return
                if route == "/admin/governance-log":
                    self._send(HTTPStatus.OK, {"events": list(api.service.governance_log())})
                    return
                if route == "/admin/metrics":
                    self._send(HTTPStatus.OK, api.service.audit_report()["audit_summary"])
                    return
                if route == "/admin/control-room":
                    self._send(HTTPStatus.OK, api.control_room_snapshot())
                    return
                if route == "/openapi.json":
                    self._send(HTTPStatus.OK, API_SCHEMA)
                    return
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

            def do_POST(self) -> None:
                route = urlsplit(self.path).path
                if not api._allowed(self):
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
                    return
                try:
                    authenticated = api._authenticated(self)
                except sqlite3.Error:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "authentication backend unavailable"},
                    )
                    return
                if not authenticated:
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                if route == "/auth/logout":
                    if not getattr(self, "gas_session_authenticated", False):
                        self._send(HTTPStatus.UNAUTHORIZED, {"error": "browser session required"})
                        return
                    if not api._session_origin_allowed(self):
                        self._send(HTTPStatus.FORBIDDEN, {"error": "invalid request origin"})
                        return
                    if self.headers.get("Content-Length", "0") != "0":
                        self._send(
                            HTTPStatus.BAD_REQUEST, {"error": "logout request must be empty"}
                        )
                        return
                    api._revoke_browser_session(self)
                    self.send_response(HTTPStatus.NO_CONTENT)
                    self.send_header("Set-Cookie", api._session_cookie("", max_age=0))
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if getattr(
                    self, "gas_session_authenticated", False
                ) and not api._session_origin_allowed(self):
                    self._send(HTTPStatus.FORBIDDEN, {"error": "invalid request origin"})
                    return
                if route.startswith("/admin") and not api._admin_authorized(
                    self, method="POST", route=route
                ):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "role authorization required"},
                    )
                    return
                if not api._api_authorized(self, method="POST", route=route):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "role authorization required"},
                    )
                    return
                if route.startswith("/admin/proposals"):
                    self._handle_admin_proposals_post(route)
                    return
                if route.startswith("/admin/policy-registry"):
                    self._handle_policy_registry_post(route)
                    return
                if route == "/admin/identities/role-assignments":
                    if api.identity_store is None:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "identity store is not configured"},
                        )
                        return
                    try:
                        payload = api._read_json(self)
                        principal_id = payload["principal_id"]
                        role = payload["role"]
                        if not isinstance(principal_id, str) or not isinstance(role, str):
                            raise ValueError("principal_id and role must be strings")
                        runtime_identity = getattr(self, "gas_runtime_identity", None)
                        if runtime_identity is None or not runtime_identity.tenant_id:
                            raise ValueError("authenticated tenant is required for role assignment")
                        api.identity_store.assign_role(
                            principal_id,
                            role,
                            assigned_by=api._actor_id(self),
                            tenant=runtime_identity.tenant_id,
                        )
                        self._send(HTTPStatus.CREATED, {"assigned": True})
                    except (KeyError, TypeError, ValueError) as exc:
                        self._send(
                            HTTPStatus.BAD_REQUEST,
                            {"error": str(exc) or "invalid role assignment"},
                        )
                    return
                if route.startswith("/admin/trust/keys"):
                    self._handle_admin_trust_post(route)
                    return
                if route.startswith("/admin/operator-keys"):
                    if api.operator_key_store is None:
                        self._send(
                            HTTPStatus.SERVICE_UNAVAILABLE,
                            {"error": "operator API key management is not configured"},
                        )
                        return
                    self._handle_admin_operator_keys_post(route)
                    return
                if route == "/admin/jobs":
                    self._handle_admin_jobs_post()
                    return
                try:
                    payload = api._read_json(self)
                    if route in {"/authorize", "/api/v1/authorize"}:
                        mesh_inputs = payload.get("mesh_inputs")
                        if mesh_inputs is not None:
                            mesh_inputs = tuple(
                                GovernanceInput.from_dict(item) for item in mesh_inputs
                            )
                        action_request = payload["request"]
                        if not isinstance(action_request, dict):
                            raise TypeError("request must be an object")
                        runtime_identity = getattr(self, "gas_runtime_identity", None)
                        if runtime_identity is not None:
                            supplied_context = action_request.get("context", {})
                            if not isinstance(supplied_context, dict):
                                raise TypeError("request context must be an object")
                            action_request = {
                                **action_request,
                                "context": {
                                    **supplied_context,
                                    **runtime_identity.context(),
                                },
                            }
                        result = api.service.authorize(
                            action_request,
                            payload["policy_id"],
                            ttl_seconds=payload.get("ttl_seconds", 300),
                            approvals=payload.get("approvals"),
                            mesh_inputs=mesh_inputs,
                        ).to_dict()
                        self._send(HTTPStatus.OK, result)
                    elif route in {"/execute", "/api/v1/execute"}:
                        self._send(
                            HTTPStatus.OK, {"result": api.service.execute_dict(payload["artifact"])}
                        )
                    else:
                        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                except PolicyDeniedError as exc:
                    self._send(
                        HTTPStatus.FORBIDDEN, {"error": "policy denied", "decision": exc.decision}
                    )
                except (AuthorizationError, KeyError, TypeError, ValueError):
                    self._send(HTTPStatus.BAD_REQUEST, {"error": "invalid request"})

            def _handle_admin_proposals_post(self, route: str) -> None:
                """Dispatch /admin/proposals[...] POST routes.

                Errors are reported with their message text: these routes are
                already gated by operator authorization, so exposing precise
                validation failures (e.g. "approval quorum not met") helps the
                admin UI without leaking anything to unauthenticated callers.
                """
                remainder = route[len("/admin/proposals") :].strip("/")
                parts = [part for part in remainder.split("/") if part]
                try:
                    if route == "/admin/proposals/prepare":
                        payload = api._read_json(self)
                        self._send(HTTPStatus.OK, api.prepare_proposal(payload))
                    elif route == "/admin/proposals":
                        payload = api._read_json(self)
                        self._send(
                            HTTPStatus.CREATED,
                            api.submit_proposal(payload, actor_id=api._actor_id(self)),
                        )
                    elif len(parts) == 2 and parts[1] == "prepare-approval":
                        payload = api._read_json(self)
                        self._send(
                            HTTPStatus.OK,
                            api.prepare_approval(parts[0], payload["approver_key_id"]),
                        )
                    elif len(parts) == 2 and parts[1] == "approve":
                        payload = api._read_json(self)
                        self._send(
                            HTTPStatus.OK,
                            api.submit_approval(parts[0], payload, actor_id=api._actor_id(self)),
                        )
                    elif len(parts) == 2 and parts[1] == "activate":
                        self._send(
                            HTTPStatus.OK,
                            api.activate_proposal(parts[0], actor_id=api._actor_id(self)),
                        )
                    else:
                        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                except KeyError as exc:
                    message = str(exc).strip("'\"") or "not found"
                    self._send(HTTPStatus.NOT_FOUND, {"error": message})
                except (TypeError, ValueError) as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid request"})

            def _handle_policy_registry_get(self, route: str) -> None:
                registry = api.versioned_policy_registry
                if registry is None:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "versioned policy registry is not configured"},
                    )
                    return
                match = re.fullmatch(
                    r"/admin/policy-registry/([a-z0-9][a-z0-9._-]{0,127})"
                    r"(?:/(versions|history|active|[^/]+)(?:/(verify))?)?",
                    route,
                )
                if match is None:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                policy_id, selector, verification = match.groups()
                try:
                    if selector is None:
                        self._send(
                            HTTPStatus.OK,
                            {
                                "policy_id": policy_id,
                                "versions": registry.list_versions(policy_id),
                                "lifecycle": {
                                    version: state.value
                                    for version, state in registry.list_lifecycle(policy_id).items()
                                },
                            },
                        )
                    elif selector == "versions":
                        self._send(HTTPStatus.OK, {"versions": registry.list_versions(policy_id)})
                    elif selector == "history":
                        self._send(
                            HTTPStatus.OK,
                            {
                                "events": [
                                    asdict(event)
                                    for event in registry.activation_history(policy_id)
                                ]
                            },
                        )
                    elif selector == "active":
                        self._send(
                            HTTPStatus.OK,
                            api._policy_record_payload(registry.get_active(policy_id)),
                        )
                    elif verification == "verify":
                        self._send(HTTPStatus.OK, registry.verify(policy_id, selector).to_dict())
                    else:
                        self._send(
                            HTTPStatus.OK,
                            api._policy_record_payload(registry.get(policy_id, selector)),
                        )
                except KeyError as exc:
                    self._send(HTTPStatus.NOT_FOUND, {"error": str(exc).strip("'\"")})
                except ValueError as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

            def _handle_policy_registry_post(self, route: str) -> None:
                registry = api.versioned_policy_registry
                if registry is None:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "versioned policy registry is not configured"},
                    )
                    return
                try:
                    payload = api._read_json(self)
                    actor_id = api._actor_id(self)
                    if route == "/admin/policy-registry/publish":
                        if api.policy_registry_signer is None:
                            raise RuntimeError("policy registry signer is not configured")
                        record = registry.publish(payload["policy"], api.policy_registry_signer)
                        api.service.record_governance_event(
                            "policy_registry.published",
                            f"{record.id}@{record.version}",
                            actor_id=actor_id,
                        )
                        self._send(HTTPStatus.CREATED, api._policy_record_payload(record))
                        return
                    policy_id, version = payload["policy_id"], payload["version"]
                    if not isinstance(policy_id, str) or not isinstance(version, str):
                        raise ValueError("policy_id and version must be strings")
                    if route == "/admin/policy-registry/activate":
                        event = registry.activate(
                            policy_id,
                            version,
                            requested_by=actor_id,
                            reason=payload["reason"],
                            expected_revision=payload.get("expected_revision"),
                        )
                    elif route == "/admin/policy-registry/rollback":
                        event = registry.rollback(
                            policy_id,
                            version,
                            requested_by=actor_id,
                            reason=payload["reason"],
                            expected_revision=payload.get("expected_revision"),
                        )
                    elif route == "/admin/policy-registry/deprecate":
                        registry.deprecate(policy_id, version)
                        self._send(HTTPStatus.OK, {"lifecycle": "DEPRECATED"})
                        return
                    elif route == "/admin/policy-registry/revoke":
                        registry.revoke(policy_id, version)
                        self._send(HTTPStatus.OK, {"lifecycle": "REVOKED"})
                        return
                    else:
                        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                        return
                    api.service.record_governance_event(
                        f"policy_registry.{event.operation}",
                        f"{event.policy_id}@{event.selected_version}",
                        actor_id=actor_id,
                    )
                    self._send(HTTPStatus.OK, asdict(event))
                except KeyError as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc).strip("'\"")})
                except (RuntimeError, TypeError, ValueError) as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid request"})

            def _handle_admin_trust_post(self, route: str) -> None:
                """Dispatch /admin/trust/keys[...] POST routes.

                Mirrors _handle_admin_proposals_post: errors are reported with
                their message text since these routes are already gated by
                operator authorization.
                """
                remainder = route[len("/admin/trust/keys") :].strip("/")
                parts = [part for part in remainder.split("/") if part]
                try:
                    if route == "/admin/trust/keys/prepare":
                        payload = api._read_json(self)
                        self._send(HTTPStatus.OK, api.prepare_trust_add(payload))
                    elif route == "/admin/trust/keys":
                        payload = api._read_json(self)
                        self._send(
                            HTTPStatus.CREATED,
                            api.submit_trust_add(payload, actor_id=api._actor_id(self)),
                        )
                    elif len(parts) == 3 and parts[1:] == ["revoke", "prepare"]:
                        payload = api._read_json(self)
                        self._send(HTTPStatus.OK, api.prepare_trust_revoke(parts[0], payload))
                    elif len(parts) == 2 and parts[1] == "revoke":
                        payload = api._read_json(self)
                        self._send(
                            HTTPStatus.OK,
                            api.submit_trust_revoke(
                                parts[0], payload, actor_id=api._actor_id(self)
                            ),
                        )
                    else:
                        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                except KeyError as exc:
                    message = str(exc).strip("'\"") or "not found"
                    self._send(HTTPStatus.NOT_FOUND, {"error": message})
                except (TypeError, ValueError) as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid request"})
                return

            def _handle_admin_jobs_post(self) -> None:
                if api.job_store is None:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "job queue is not configured"},
                    )
                    return
                try:
                    payload = api._read_json(self)
                    job = api.submit_job(payload, actor_id=api._actor_id(self))
                    self._send(HTTPStatus.ACCEPTED, job)
                except (KeyError, TypeError, ValueError) as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid request"})
                except (JobStoreError, sqlite3.Error):
                    self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "job store unavailable"})

            def _handle_admin_job_get(self, route: str) -> None:
                if api.job_store is None:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "job queue is not configured"},
                    )
                    return
                job_id = route.removeprefix("/admin/jobs/").strip("/")
                if not job_id or "/" in job_id:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                try:
                    job = api.job_store.get(job_id)
                except KeyError:
                    self._send(HTTPStatus.NOT_FOUND, {"error": "unknown job"})
                    return
                except (JobStoreError, sqlite3.Error):
                    self._send(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "job store unavailable"})
                    return
                self._send(
                    HTTPStatus.OK,
                    {
                        "job_id": job.job_id,
                        "status": job.status,
                        "attempts": job.attempts,
                        "max_attempts": job.max_attempts,
                        "last_error": job.last_error,
                    },
                )

            def _handle_admin_operator_keys_post(self, route: str) -> None:
                remainder = route[len("/admin/operator-keys") :].strip("/")
                parts = [part for part in remainder.split("/") if part]
                actor_id = api._actor_id(self)
                try:
                    if route == "/admin/operator-keys":
                        payload = api._read_json(self)
                        self._send(
                            HTTPStatus.CREATED,
                            api.create_operator_key(payload, actor_id=actor_id),
                        )
                    elif len(parts) == 2 and parts[1] == "revoke":
                        api.revoke_operator_key(parts[0], actor_id=actor_id)
                        self._send(HTTPStatus.OK, {"revoked": True, "key_id": parts[0]})
                    else:
                        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                except KeyError as exc:
                    message = str(exc).strip("'\"") or "not found"
                    self._send(HTTPStatus.NOT_FOUND, {"error": message})
                except (TypeError, ValueError) as exc:
                    self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc) or "invalid request"})
                except sqlite3.Error:
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        {"error": "operator key store unavailable"},
                    )

            def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                self._rid = api._request_id(self)
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("X-Request-ID", quote(self._rid, safe=""))
                self.send_header("X-API-Version", API_VERSION)
                trace_context = api._trace_context(self)
                if trace_context is not None:
                    self.send_header("traceparent", trace_context.traceparent())
                self._send_cors()
                for k, v in security_headers().items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(encoded)
                api._record_trace(
                    "gas.http.response",
                    {
                        "http.request.method": self.command,
                        "url.path": urlsplit(self.path).path,
                        "http.response.status_code": int(status),
                        "request.id": self._rid,
                    },
                    trace_context,
                )

            def _send_static(self, body: bytes, content_type: str) -> None:
                """Serve a same-origin admin UI asset with a relaxed, still-strict CSP.

                The default ``default-src 'none'`` policy used for JSON
                responses would also block the admin page's own external
                script/style tags and its authenticated ``fetch`` calls, so
                these assets get a scoped policy that only allows same-origin
                loads instead of disabling CSP altogether.
                """
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                for k, v in security_headers().items():
                    if k == "Content-Security-Policy":
                        v = (
                            "default-src 'none'; script-src 'self'; style-src 'self'; "
                            "connect-src 'self'; base-uri 'none'"
                        )
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

        return Handler

    def _handle_oidc_login(self, request: BaseHTTPRequestHandler) -> None:
        if self.oidc_auth_client is None or self.oidc_sessions is None:
            self._send_auth_error(request, HTTPStatus.NOT_FOUND, "OIDC sign-in is not configured")
            return
        query = parse_qs(urlsplit(request.path).query, keep_blank_values=True)
        next_path = query.get("next", ["/admin"])[0]
        parsed_next = urlsplit(next_path)
        if (
            not isinstance(next_path, str)
            or not next_path.startswith("/")
            or next_path.startswith("//")
            or "\\" in next_path
            or parsed_next.scheme
            or parsed_next.netloc
        ):
            next_path = "/admin"
        try:
            state, nonce, challenge = self.oidc_sessions.begin_login(next_path=next_path)
            location = self.oidc_auth_client.authorization_url(
                state=state,
                nonce=nonce,
                code_challenge=challenge,
            )
        except (IdentityValidationError, ValueError):
            self._send_auth_error(
                request, HTTPStatus.SERVICE_UNAVAILABLE, "OIDC sign-in unavailable"
            )
            return
        request.send_response(HTTPStatus.FOUND)
        request.send_header("Location", location)
        request.send_header("Cache-Control", "no-store")
        request.send_header("Pragma", "no-cache")
        request.send_header(
            "Set-Cookie",
            self._state_cookie(state, max_age=_LOGIN_STATE_TTL_SECONDS),
        )
        for key, value in security_headers().items():
            request.send_header(key, value)
        request.end_headers()

    def _trace_context(self, request: BaseHTTPRequestHandler) -> TraceContext | None:
        return TraceContext.from_traceparent(request.headers.get("traceparent"))

    def _record_trace(
        self,
        name: str,
        attributes: dict[str, Any],
        context: TraceContext | None,
    ) -> None:
        if self.tracer is not None:
            self.tracer.record(name, attributes, context)

    def _handle_oidc_callback(self, request: BaseHTTPRequestHandler) -> None:
        if (
            self.oidc_auth_client is None
            or self.oidc_login_validator is None
            or self.oidc_sessions is None
        ):
            self._send_auth_error(request, HTTPStatus.NOT_FOUND, "OIDC sign-in is not configured")
            return
        query = parse_qs(urlsplit(request.path).query, keep_blank_values=True)
        states = query.get("state", [])
        state_cookie = self._cookie_value(request, self.state_cookie_name)
        if (
            len(states) != 1
            or state_cookie is None
            or not hmac.compare_digest(states[0], state_cookie)
        ):
            self._send_auth_error(
                request,
                HTTPStatus.BAD_REQUEST,
                "invalid OIDC callback",
                cookie=self._state_cookie("", max_age=0),
            )
            return
        if query.get("error"):
            try:
                self.oidc_sessions.consume_login(states[0])
            except IdentityValidationError:
                self._send_auth_error(
                    request,
                    HTTPStatus.BAD_REQUEST,
                    "invalid OIDC callback",
                    cookie=self._state_cookie("", max_age=0),
                )
                return
            self._send_auth_error(
                request,
                HTTPStatus.UNAUTHORIZED,
                "Entra sign-in was not completed",
                cookie=self._state_cookie("", max_age=0),
            )
            return
        codes = query.get("code", [])
        if len(codes) != 1 or not codes[0] or len(codes[0]) > 8192:
            self._send_auth_error(
                request,
                HTTPStatus.BAD_REQUEST,
                "invalid OIDC callback",
                cookie=self._state_cookie("", max_age=0),
            )
            return
        try:
            pending = self.oidc_sessions.consume_login(states[0])
            token_response = self.oidc_auth_client.exchange_code(
                code=codes[0],
                code_verifier=pending.code_verifier,
            )
            identity = self.oidc_login_validator.validate(
                token_response["id_token"],
                nonce=pending.nonce,
            )
            session_token, max_age = self.oidc_sessions.create_session(identity)
        except (IdentityValidationError, ValueError):
            self._send_auth_error(
                request,
                HTTPStatus.UNAUTHORIZED,
                "Entra sign-in could not be validated",
                cookie=self._state_cookie("", max_age=0),
            )
            return
        request.send_response(HTTPStatus.FOUND)
        request.send_header("Location", pending.next_path)
        request.send_header("Cache-Control", "no-store")
        request.send_header("Set-Cookie", self._session_cookie(session_token, max_age=max_age))
        request.send_header("Set-Cookie", self._state_cookie("", max_age=0))
        for key, value in security_headers().items():
            request.send_header(key, value)
        request.end_headers()

    @staticmethod
    def _send_auth_error(
        request: BaseHTTPRequestHandler,
        status: HTTPStatus,
        message: str,
        *,
        cookie: str | None = None,
    ) -> None:
        encoded = json.dumps({"error": message}).encode("utf-8")
        request.send_response(status)
        request.send_header("Content-Type", "application/json")
        request.send_header("Content-Length", str(len(encoded)))
        request.send_header("Cache-Control", "no-store")
        if cookie is not None:
            request.send_header("Set-Cookie", cookie)
        for key, value in security_headers().items():
            request.send_header(key, value)
        request.end_headers()
        request.wfile.write(encoded)

    @property
    def session_cookie_name(self) -> str:
        return _OIDC_SESSION_COOKIE if self.oidc_cookie_secure else "gas-session"

    @property
    def state_cookie_name(self) -> str:
        return _OIDC_STATE_COOKIE if self.oidc_cookie_secure else "gas-login"

    def _session_cookie(self, token: str, *, max_age: int) -> str:
        cookie = (
            f"{self.session_cookie_name}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        )
        return f"{cookie}; Secure" if self.oidc_cookie_secure else cookie

    def _state_cookie(self, token: str, *, max_age: int) -> str:
        cookie = (
            f"{self.state_cookie_name}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}"
        )
        return f"{cookie}; Secure" if self.oidc_cookie_secure else cookie

    def _revoke_browser_session(self, request: BaseHTTPRequestHandler) -> None:
        if self.oidc_sessions is None:
            return
        token = self._session_token(request)
        if token:
            self.oidc_sessions.revoke_session(token)

    def _session_token(self, request: BaseHTTPRequestHandler) -> str | None:
        return self._cookie_value(request, self.session_cookie_name)

    @staticmethod
    def _cookie_value(request: BaseHTTPRequestHandler, name: str) -> str | None:
        cookie_header = request.headers.get("Cookie", "")
        cookies = SimpleCookie()
        try:
            cookies.load(cookie_header)
        except CookieError:
            return None
        morsel = cookies.get(name)
        return morsel.value if morsel is not None and morsel.value else None

    def _session_origin_allowed(self, request: BaseHTTPRequestHandler) -> bool:
        if self.oidc_auth_client is None:
            return False
        expected = urlsplit(self.oidc_auth_client.redirect_uri)
        origin = request.headers.get("Origin", "")
        expected_origin = f"{expected.scheme}://{expected.netloc}"
        return bool(origin and hmac.compare_digest(origin, expected_origin))

    def _authenticated(self, request: BaseHTTPRequestHandler) -> bool:
        supplied = request.headers.get("Authorization", "")
        scheme, separator, credential = supplied.partition(" ")
        bearer_credential = credential.strip() if separator and scheme.lower() == "bearer" else ""
        if (
            self.oidc_validator is None
            and not self.oidc_only
            and self.operator_key_store is not None
            and bearer_credential
        ):
            operator_key = self.operator_key_store.authenticate(bearer_credential)
            if operator_key is not None:
                if not urlsplit(request.path).path.startswith("/admin"):
                    return False
                request.gas_operator_id = operator_key.operator_id  # type: ignore[attr-defined]
                request.gas_operator_key_id = operator_key.key_id  # type: ignore[attr-defined]
                request.gas_roles = (Role.OPERATOR.value,)  # type: ignore[attr-defined]
                return True
        if self.oidc_validator is not None and bearer_credential:
            try:
                external_identity = self.oidc_validator.validate(bearer_credential)
            except IdentityValidationError:
                return self._health_probe_authorized(request, supplied)
            request.gas_identity = external_identity  # type: ignore[attr-defined]
            runtime_identity = RuntimeIdentity.from_external_identity(
                external_identity,
                request_id=self._request_id(request),
                legacy_admin_role=self.operator_role,
            )
            runtime_identity = self._enrich_identity(runtime_identity)
            if runtime_identity is None:
                return False
            request.gas_runtime_identity = runtime_identity  # type: ignore[attr-defined]
            return True
        session_token = self._session_token(request)
        if self.oidc_sessions is not None and session_token is not None:
            runtime_identity = self.oidc_sessions.get_session(session_token)
            if runtime_identity is not None:
                runtime_identity = replace(runtime_identity, request_id=self._request_id(request))
                runtime_identity = self._enrich_identity(runtime_identity)
                if runtime_identity is None:
                    return False
                request.gas_runtime_identity = runtime_identity  # type: ignore[attr-defined]
                request.gas_session_authenticated = True  # type: ignore[attr-defined]
                return True
        if self.oidc_only:
            return self._health_probe_authorized(request, supplied)
        if not self.bearer_token:
            return self.operator_token is not None and hmac.compare_digest(
                supplied, f"Bearer {self.operator_token}"
            )
        if self.operator_token is not None and hmac.compare_digest(
            supplied, f"Bearer {self.operator_token}"
        ):
            return True
        return hmac.compare_digest(supplied, f"Bearer {self.bearer_token}") or hmac.compare_digest(
            supplied, self.bearer_token
        )

    def _enrich_identity(self, identity: RuntimeIdentity) -> RuntimeIdentity | None:
        if self.identity_store is None:
            return identity
        if not identity.subject or not identity.tenant_id or not identity.issuer:
            return None
        assigned_roles = self.identity_store.roles_for(identity.subject, identity.tenant_id)
        enriched = replace(
            identity,
            roles=tuple(sorted(set(identity.roles) | set(assigned_roles))),
        )
        self.identity_store.record_authentication(
            subject=enriched.subject or "",
            tenant=enriched.tenant_id or "",
            email=enriched.email,
            display_name=enriched.name,
            issuer=enriched.issuer or "",
            roles=enriched.roles,
            identity_source=enriched.identity_source or "oidc",
            service_principal=enriched.service_principal,
            client_id=enriched.principal_id,
        )
        return enriched

    def _health_probe_authorized(self, request: BaseHTTPRequestHandler, supplied: str) -> bool:
        return (
            request.command == "GET"
            and urlsplit(request.path).path in {"/health", "/livez", "/readyz", "/startupz"}
            and self.bearer_token is not None
            and hmac.compare_digest(supplied, f"Bearer {self.bearer_token}")
        )

    @staticmethod
    def _actor_id(request: BaseHTTPRequestHandler) -> str:
        operator_id = getattr(request, "gas_operator_id", None)
        if operator_id is not None:
            key_id = getattr(request, "gas_operator_key_id", None)
            return f"api-key:{operator_id}:{key_id}" if key_id else f"api-key:{operator_id}"
        runtime_identity = getattr(request, "gas_runtime_identity", None)
        if runtime_identity is not None:
            return runtime_identity.actor_id or "shared-token"
        return "shared-token"

    @staticmethod
    def _api_required_roles(method: str, route: str) -> frozenset[Role]:
        if method == "GET" and route in {"/audit", "/api/v1/audit"}:
            return frozenset({Role.AUDITOR})
        if method == "POST" and route in {
            "/authorize",
            "/execute",
            "/api/v1/authorize",
            "/api/v1/execute",
        }:
            return frozenset({Role.OPERATOR})
        return frozenset()

    def _api_authorized(self, request: BaseHTTPRequestHandler, *, method: str, route: str) -> bool:
        required = self._api_required_roles(method, route)
        if not required:
            return True
        runtime_identity = getattr(request, "gas_runtime_identity", None)
        if runtime_identity is None:
            return self.oidc_validator is None and not self.oidc_only
        if (
            method == "POST"
            and route
            in {
                "/authorize",
                "/execute",
                "/api/v1/authorize",
                "/api/v1/execute",
            }
            and not (
                runtime_identity.subject
                and runtime_identity.tenant_id
                and runtime_identity.issuer
                and runtime_identity.identity_source
            )
        ):
            return False
        roles = set(runtime_identity.roles)
        return Role.PLATFORM_ADMIN.value in roles or bool(
            roles.intersection(role.value for role in required)
        )

    @staticmethod
    def _admin_required_roles(method: str, route: str) -> frozenset[Role]:
        if method == "GET":
            if route in {"/admin", "/admin/app.js", "/admin/app.css"}:
                return frozenset({Role.POLICY_ADMIN, Role.OPERATOR, Role.AUDITOR, Role.APPROVER})
            if route == "/admin/policies":
                return frozenset({Role.POLICY_ADMIN, Role.OPERATOR, Role.AUDITOR})
            if route.startswith("/admin/policy-registry/"):
                return frozenset({Role.POLICY_ADMIN, Role.AUDITOR})
            if route == "/admin/proposals":
                return frozenset({Role.POLICY_ADMIN, Role.APPROVER, Role.AUDITOR})
            if route == "/admin/trust":
                return frozenset({Role.PLATFORM_ADMIN, Role.AUDITOR})
            if route == "/admin/operator-keys":
                return frozenset({Role.PLATFORM_ADMIN})
            if route.startswith("/admin/jobs/"):
                return frozenset({Role.OPERATOR, Role.AUDITOR})
            if route in {
                "/admin/governance-log",
                "/admin/metrics",
                "/admin/control-room",
            }:
                return frozenset(
                    {
                        Role.POLICY_ADMIN,
                        Role.OPERATOR,
                        Role.AUDITOR,
                        Role.APPROVER,
                    }
                )
            if route in {
                "/admin/identities/role-assignments",
                "/admin/identities/service-principals",
                "/admin/identities/events",
            }:
                return frozenset({Role.PLATFORM_ADMIN})
            return frozenset()

        if method != "POST":
            return frozenset()
        if route in {"/admin/proposals/prepare", "/admin/proposals"}:
            return frozenset({Role.POLICY_ADMIN})
        if route in {
            "/admin/policy-registry/publish",
            "/admin/policy-registry/activate",
            "/admin/policy-registry/rollback",
            "/admin/policy-registry/deprecate",
            "/admin/policy-registry/revoke",
        }:
            return frozenset({Role.POLICY_ADMIN})
        if re.fullmatch(r"/admin/proposals/[^/]+/activate", route):
            return frozenset({Role.POLICY_ADMIN})
        if re.fullmatch(r"/admin/proposals/[^/]+/(?:prepare-approval|approve)", route):
            return frozenset({Role.APPROVER})
        if route.startswith("/admin/trust/keys"):
            return frozenset({Role.PLATFORM_ADMIN})
        if route == "/admin/operator-keys" or re.fullmatch(
            r"/admin/operator-keys/[^/]+/revoke", route
        ):
            return frozenset({Role.PLATFORM_ADMIN})
        if route == "/admin/identities/role-assignments":
            return frozenset({Role.PLATFORM_ADMIN})
        if route == "/admin/jobs":
            return frozenset({Role.OPERATOR})
        return frozenset()

    def _admin_authorized(
        self, request: BaseHTTPRequestHandler, *, method: str, route: str
    ) -> bool:
        required = self._admin_required_roles(method, route)
        if not required:
            return False

        supplied = request.headers.get("Authorization", "")
        scheme, separator, credential = supplied.partition(" ")
        if (
            self.oidc_validator is None
            and not self.oidc_only
            and self.operator_token is not None
            and separator
            and scheme.lower() == "bearer"
            and hmac.compare_digest(credential.strip(), self.operator_token)
        ):
            return True

        runtime_identity = getattr(request, "gas_runtime_identity", None)
        roles = (
            set(runtime_identity.roles)
            if runtime_identity is not None
            else set(getattr(request, "gas_roles", ()))
        )
        return Role.PLATFORM_ADMIN.value in roles or bool(
            roles.intersection(role.value for role in required)
        )

    def _operator_authorized(self, request: BaseHTTPRequestHandler, *, write: bool = True) -> bool:
        if getattr(request, "gas_operator_id", None) is not None:
            return True
        runtime_identity = getattr(request, "gas_runtime_identity", None)
        if runtime_identity is not None:
            roles = set(runtime_identity.roles)
            if "platform_admin" in roles:
                return True
            needed = (
                {Role.OPERATOR.value}
                if write
                else {
                    Role.OPERATOR.value,
                    Role.AUDITOR.value,
                }
            )
            return bool(roles.intersection(needed))
        supplied = request.headers.get("Authorization", "")
        return self.operator_token is not None and hmac.compare_digest(
            supplied, f"Bearer {self.operator_token}"
        )

    def _allowed(self, request: BaseHTTPRequestHandler) -> bool:
        return self.rate_limiter.allow(request.client_address[0])

    @staticmethod
    def _request_id(request: BaseHTTPRequestHandler) -> str:
        match = re.fullmatch(r"[A-Za-z0-9._-]{1,128}", request.headers.get("X-Request-ID") or "")
        return match.group(0) if match else uuid.uuid4().hex

    def _read_json(self, request: BaseHTTPRequestHandler) -> dict[str, Any]:
        header = request.headers.get("Content-Length")
        if header is None:
            raise ValueError("Content-Length is required")
        try:
            length = int(header)
        except ValueError as exc:
            raise ValueError("Content-Length is invalid") from exc
        if length < 0 or length > self.max_body_bytes:
            raise ValueError("request body exceeds size limit")
        try:
            payload = json.loads(request.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValueError("request JSON is invalid") from exc
        if not isinstance(payload, dict):
            raise ValueError("request JSON must be an object")
        return payload

    def _require_policy_change_manager(self) -> PolicyChangeManager:
        manager = self.service.policy_change_manager
        if manager is None:
            raise ValueError("policy change workflow is unavailable without a trust store")
        return manager

    def prepare_proposal(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return the exact bytes a proposer must sign; see PolicyChangeManager.prepare_proposal."""
        manager = self._require_policy_change_manager()
        return manager.prepare_proposal(
            new_policy=policy_from_dict(payload["policy"]),
            proposer_key_id=payload["proposer_key_id"],
            rationale=payload.get("rationale", ""),
            proposal_id=payload.get("proposal_id"),
        )

    def submit_proposal(
        self, payload: dict[str, Any], *, actor_id: str = "system"
    ) -> dict[str, Any]:
        manager = self._require_policy_change_manager()
        proposal = manager.propose_signed(
            new_policy=policy_from_dict(payload["policy"]),
            proposer_key_id=payload["proposer_key_id"],
            signature=payload["signature"],
            rationale=payload.get("rationale", ""),
            proposal_id=payload.get("proposal_id"),
            actor_id=actor_id,
        )
        return proposal.to_summary_dict()

    def prepare_approval(self, proposal_id: str, approver_key_id: str) -> dict[str, Any]:
        manager = self._require_policy_change_manager()
        return manager.prepare_approval(proposal_id, approver_key_id=approver_key_id)

    def submit_approval(
        self, proposal_id: str, payload: dict[str, Any], *, actor_id: str = "system"
    ) -> dict[str, Any]:
        manager = self._require_policy_change_manager()
        proposal = manager.approve_signed(
            proposal_id,
            approver_key_id=payload["approver_key_id"],
            signature=payload["signature"],
            actor_id=actor_id,
        )
        return proposal.to_summary_dict()

    def activate_proposal(self, proposal_id: str, *, actor_id: str = "system") -> dict[str, Any]:
        manager = self._require_policy_change_manager()
        policy = manager.activate(proposal_id, actor_id=actor_id)
        return {"policy_id": policy.policy_id, "policy_digest": policy.digest()}

    def list_proposals(self) -> dict[str, Any]:
        manager = self.service.policy_change_manager
        if manager is None:
            return {"proposals": [], "required_approvals": None}
        return {
            "proposals": [proposal.to_summary_dict() for proposal in manager.proposals()],
            "required_approvals": manager.required_approvals,
        }

    def control_room_snapshot(self) -> dict[str, Any]:
        """Return the compact, read-only mission-control view."""
        service = self.service
        registry = service.policies
        summary = service.boundary.replay_log.audit_summary()
        proposals = self.list_proposals()
        trust = self.trust_snapshot()
        policies = [
            {"id": policy.policy_id, "actions": list(policy.allowed_actions)}
            for policy in registry.policies()
        ]
        coverage = {
            action: [p["id"] for p in policies if action in p["actions"]]
            for action in service.actions
        }
        events = service.boundary.replay_log.events()
        incidents = [
            {
                "summary": event.get("error_type", "Authorization denied"),
                "detail": event.get(
                    "error", "; ".join(event.get("decision", {}).get("reasons", []))
                ),
                "type": event.get("type"),
                "severity": ("high" if event.get("type") == "execution" else "medium"),
            }
            for event in events
            if (event.get("type") == "execution" and event.get("status") == "failed")
            or (event.get("type") == "authorization" and event.get("issued") is False)
        ]
        execution_count = summary["execution_count"]
        assets = [{"asset_id": key, "policies": coverage[key]} for key in sorted(coverage)]
        graph_edges = [
            {"from": policy["id"], "to": action}
            for policy in policies
            for action in policy["actions"]
        ]
        analytics = {
            "policy_count": len(policies),
            "asset_count": len(assets),
            "authorizations": summary["authorization_count"],
            "executions": execution_count,
            "failures": summary["failure_count"],
            "success_rate": round(summary["success_count"] / execution_count * 100, 1)
            if execution_count
            else None,
            "trusted_keys": len(trust["keys"]),
            "frames": summary["frame_count"],
        }
        return {
            "health": {"ok": service.audit_report()["health"]["ok"]},
            "assets": assets,
            "policies": policies,
            "graph": {"edges": graph_edges},
            "approvals": [p for p in proposals["proposals"] if p["status"] == "pending"],
            "incidents": incidents[-10:],
            "timeline": [
                {
                    "type": e.get("type", "unknown"),
                    "event": e.get("event", e.get("status", e.get("type", "unknown"))),
                    "subject": e.get("subject_id", e.get("nonce", "")),
                }
                for e in events[-20:][::-1]
            ],
            "analytics": analytics,
        }

    def _require_trust_change_manager(self) -> TrustChangeManager:
        manager = self.service.trust_change_manager
        if manager is None:
            raise ValueError("trust key management is unavailable without a trust store")
        return manager

    def prepare_trust_add(self, payload: dict[str, Any]) -> dict[str, Any]:
        manager = self._require_trust_change_manager()
        return manager.prepare_add(
            key_id=payload["key_id"],
            public_key_b64=payload["public_key_b64"],
            requested_by_key_id=payload["requested_by_key_id"],
        )

    def submit_trust_add(
        self, payload: dict[str, Any], *, actor_id: str = "system"
    ) -> dict[str, Any]:
        manager = self._require_trust_change_manager()
        return manager.submit_add(
            key_id=payload["key_id"],
            public_key_b64=payload["public_key_b64"],
            requested_by_key_id=payload["requested_by_key_id"],
            signature=payload["signature"],
            actor_id=actor_id,
        )

    def prepare_trust_revoke(self, key_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        manager = self._require_trust_change_manager()
        return manager.prepare_revoke(key_id, requested_by_key_id=payload["requested_by_key_id"])

    def submit_trust_revoke(
        self, key_id: str, payload: dict[str, Any], *, actor_id: str = "system"
    ) -> dict[str, Any]:
        manager = self._require_trust_change_manager()
        return manager.submit_revoke(
            key_id,
            requested_by_key_id=payload["requested_by_key_id"],
            signature=payload["signature"],
            actor_id=actor_id,
        )

    def trust_snapshot(self) -> dict[str, Any]:
        trust_store = self.service.boundary.trust_store
        return trust_store.to_dict() if trust_store is not None else {"keys": {}, "revoked": []}

    @staticmethod
    def _policy_record_payload(record: StoredPolicy) -> dict[str, Any]:
        return {
            "policy_id": record.id,
            "version": record.version,
            "content_digest": record.content_hash,
            "policy": record.policy,
            "schema_version": record.schema_version,
            "signature": asdict(record.signature) if record.signature is not None else None,
        }

    def _require_operator_key_store(self) -> OperatorKeyStore:
        if self.operator_key_store is None:
            raise ValueError("operator API key management is not configured")
        return self.operator_key_store

    def list_operator_keys(self) -> dict[str, Any]:
        return {"keys": list(self._require_operator_key_store().list_keys())}

    def create_operator_key(self, payload: dict[str, Any], *, actor_id: str) -> dict[str, str]:
        key_store = self._require_operator_key_store()
        operator_id = payload.get("operator_id")
        if not isinstance(operator_id, str):
            raise ValueError("operator_id must be a string")
        created = key_store.create(operator_id)
        self.service.record_governance_event(
            "operator.key_added", created["key_id"], actor_id=actor_id
        )
        return created

    def submit_job(self, payload: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
        """Enqueue a signed GAA for the worker; the worker re-authorizes it."""
        artifact = payload.get("artifact")
        key = payload.get("idempotency_key")
        attempts = payload.get("max_attempts", 3)
        if isinstance(artifact, dict):
            artifact_json = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
        elif isinstance(artifact, str):
            try:
                parsed_artifact = json.loads(artifact)
            except json.JSONDecodeError as exc:
                raise ValueError("artifact must be a JSON object or serialized GAA") from exc
            if not isinstance(parsed_artifact, dict):
                raise ValueError("artifact must be a JSON object or serialized GAA")
            artifact_json = artifact
        else:
            raise ValueError("artifact must be a JSON object or serialized GAA")
        if not isinstance(key, str) or not key:
            raise ValueError("idempotency_key must be a non-empty string")
        if not isinstance(attempts, int) or isinstance(attempts, bool) or not 0 < attempts <= 20:
            raise ValueError("max_attempts must be an integer between 1 and 20")
        if self.job_store is None:
            raise RuntimeError("job queue is not configured")
        job = self.job_store.enqueue(
            {"artifact": artifact_json}, idempotency_key=key, max_attempts=attempts
        )
        self.service.record_governance_event("job.submitted", job.job_id, actor_id=actor_id)
        return {"job_id": job.job_id, "status": job.status}

    def revoke_operator_key(self, key_id: str, *, actor_id: str) -> None:
        self._require_operator_key_store().revoke(key_id)
        self.service.record_governance_event("operator.key_revoked", key_id, actor_id=actor_id)


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def parse_server_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Governed Autonomy HTTP API server.")
    parser.add_argument("--host", default=os.environ.get("GOVERNED_AUTONOMY_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bearer-token", default=os.environ.get("GOVERNED_AUTONOMY_BEARER_TOKEN"))
    parser.add_argument("--oidc-issuer", default=os.environ.get("OIDC_ISSUER"))
    parser.add_argument("--oidc-audience", default=os.environ.get("OIDC_AUDIENCE"))
    parser.add_argument("--oidc-jwks-url", default=os.environ.get("OIDC_JWKS_URL"))
    parser.add_argument("--entra-tenant-id", default=os.environ.get("ENTRA_TENANT_ID"))
    parser.add_argument("--entra-client-id", default=os.environ.get("ENTRA_CLIENT_ID"))
    parser.add_argument("--entra-client-secret", default=os.environ.get("ENTRA_CLIENT_SECRET"))
    parser.add_argument("--entra-redirect-uri", default=os.environ.get("ENTRA_REDIRECT_URI"))
    parser.add_argument(
        "--oidc-cookie-insecure",
        action="store_true",
        default=_env_flag("OIDC_COOKIE_INSECURE"),
        help="Disable Secure on the OIDC session cookie for local HTTP development only.",
    )
    parser.add_argument(
        "--oidc-discovery",
        action="store_true",
        default=_env_flag("OIDC_DISCOVERY"),
        help=(
            "Resolve the JWKS endpoint via the issuer's "
            "/.well-known/openid-configuration document instead of --oidc-jwks-url."
        ),
    )
    parser.add_argument(
        "--operator-token", default=os.environ.get("GOVERNED_AUTONOMY_OPERATOR_TOKEN")
    )
    parser.add_argument(
        "--job-store",
        default=os.environ.get("GOVERNED_AUTONOMY_JOB_STORE"),
        help=(
            "SQLite database path for the API job queue; when omitted, DATABASE_URL "
            "configures the shared PostgreSQL queue."
        ),
    )
    parser.add_argument(
        "--operator-key-store",
        default=os.environ.get("GOVERNED_AUTONOMY_OPERATOR_KEY_STORE"),
        help="Path to the SQLite database used for revocable operator API keys.",
    )
    parser.add_argument(
        "--identity-store",
        default=os.environ.get("GAS_IDENTITY_STORE"),
        help="SQLite file for users, service principals, role assignments, and identity events",
    )
    parser.add_argument(
        "--operator-role", default=os.environ.get("OIDC_OPERATOR_ROLE", "gas-admin")
    )
    parser.add_argument("--max-body-bytes", type=int, default=64 * 1024)
    parser.add_argument("--rate-limit", type=int, default=120)
    parser.add_argument(
        "--cors-origins",
        default=os.environ.get("GOVERNED_AUTONOMY_CORS_ORIGINS", ""),
        help="comma-separated browser origins allowed to call the API (default: none)",
    )
    return parser.parse_args(argv)


def create_server(
    service: GovernedService,
    *,
    bearer_token: str | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    max_body_bytes: int = 64 * 1024,
    rate_limit: int = 120,
    tls: TLSConfig | None = None,
    oidc_validator: OIDCValidator | None = None,
    oidc_only: bool = False,
    oidc_auth_client: OIDCAuthCodeClient | None = None,
    oidc_login_validator: OIDCValidator | None = None,
    oidc_cookie_secure: bool = True,
    oidc_session_repository: OIDCSessionRepository | None = None,
    operator_token: str | None = None,
    operator_role: str = "gas-admin",
    operator_key_store: OperatorKeyStore | None = None,
    identity_store: IdentityStore | None = None,
    job_store: JobSubmissionStore | None = None,
    versioned_policy_registry: VersionedPolicyRegistry | None = None,
    policy_registry_signer: PolicySigner | None = None,
    rate_limiter: RateLimiter | None = None,
    tracer: TraceRecorder | None = None,
    cors_origins: Sequence[str] = (),
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port),
        AuthenticatedAPI(
            service,
            bearer_token=bearer_token,
            oidc_validator=oidc_validator,
            oidc_only=oidc_only,
            oidc_auth_client=oidc_auth_client,
            oidc_login_validator=oidc_login_validator,
            oidc_cookie_secure=oidc_cookie_secure,
            oidc_session_repository=oidc_session_repository,
            operator_token=operator_token,
            operator_role=operator_role,
            operator_key_store=operator_key_store,
            identity_store=identity_store,
            job_store=job_store,
            versioned_policy_registry=versioned_policy_registry,
            policy_registry_signer=policy_registry_signer,
            max_body_bytes=max_body_bytes,
            rate_limit=rate_limit,
            rate_limiter=rate_limiter,
            tracer=tracer,
            cors_origins=cors_origins,
        ).handler(),
    )
    if tls is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        minimum_version = {
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }.get(tls.min_version)
        if minimum_version is None:
            server.server_close()
            raise ValueError("tls.min_version must be TLSv1.2 or TLSv1.3")
        context.minimum_version = minimum_version
        context.load_cert_chain(certfile=tls.certfile, keyfile=tls.keyfile)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_server_args(argv)
    configure_logging()
    oidc_validator = None
    oidc_auth_client = None
    entra_configured = bool(
        getattr(args, "entra_tenant_id", None) or getattr(args, "entra_client_id", None)
    )
    generic_oidc_configured = bool(
        getattr(args, "oidc_issuer", None)
        or getattr(args, "oidc_audience", None)
        or getattr(args, "oidc_jwks_url", None)
        or getattr(args, "oidc_discovery", False)
    )
    bearer_token = getattr(args, "bearer_token", None)
    oidc_only = False
    entra_redirect_uri = getattr(args, "entra_redirect_uri", None)
    entra_client_secret = getattr(args, "entra_client_secret", None)
    if (entra_redirect_uri or entra_client_secret) and not entra_configured:
        raise SystemExit("Entra browser sign-in requires ENTRA_TENANT_ID and ENTRA_CLIENT_ID")
    if entra_configured:
        if not getattr(args, "entra_tenant_id", None) or not getattr(args, "entra_client_id", None):
            raise SystemExit("ENTRA_TENANT_ID and ENTRA_CLIENT_ID are required together")
        if generic_oidc_configured:
            raise SystemExit("Entra ID settings cannot be combined with generic OIDC settings")
        try:
            entra_config = EntraOIDCConfig(
                tenant_id=args.entra_tenant_id,
                client_id=args.entra_client_id,
            )
            discovery = discover_oidc_configuration(entra_config.issuer)
            oidc_validator = entra_oidc_validator_from_discovery(
                entra_config,
                discovery=discovery,
            )
            if entra_redirect_uri:
                oidc_auth_client = OIDCAuthCodeClient(
                    discovery=discovery,
                    client_id=entra_config.client_id,
                    client_secret=entra_client_secret,
                    redirect_uri=entra_redirect_uri,
                )
        except (IdentityValidationError, ValueError) as exc:
            raise SystemExit(f"Entra ID OIDC configuration failed: {exc}") from exc
        oidc_only = True
    elif args.oidc_discovery:
        if not args.oidc_issuer or not args.oidc_audience:
            raise SystemExit("OIDC_ISSUER and OIDC_AUDIENCE are required for OIDC discovery")
        if args.oidc_jwks_url:
            raise SystemExit("--oidc-jwks-url must not be set when --oidc-discovery is used")
        try:
            oidc_validator = oidc_validator_from_discovery(
                issuer=args.oidc_issuer, audience=args.oidc_audience
            )
        except IdentityValidationError as exc:
            raise SystemExit(f"OIDC discovery failed: {exc}") from exc
    else:
        oidc_args = (args.oidc_issuer, args.oidc_audience, args.oidc_jwks_url)
        if any(oidc_args) and not all(oidc_args):
            raise SystemExit(
                "OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL must be configured together "
                "(or use --oidc-discovery with just issuer and audience)"
            )
        if all(oidc_args):
            oidc_validator = OIDCValidator(
                issuer=args.oidc_issuer,
                audience=args.oidc_audience,
                jwks_provider=UrlJWKSProvider(args.oidc_jwks_url),
            )
    if not bearer_token and oidc_validator is None:
        raise SystemExit(
            "GOVERNED_AUTONOMY_BEARER_TOKEN or complete OIDC configuration is required"
        )
    service, _, _ = build_runtime_service()
    operator_key_store = (
        OperatorKeyStore(args.operator_key_store) if args.operator_key_store else None
    )
    identity_connection = None
    if args.identity_store:
        identity_store: IdentityStore | None = SQLiteIdentityStore(args.identity_store)
    elif os.environ.get("DATABASE_URL"):
        try:
            import psycopg
        except ImportError as exc:
            raise SystemExit("install the postgres extra: pip install .[postgres]") from exc
        identity_connection = psycopg.connect(os.environ["DATABASE_URL"])
        identity_store = PostgresIdentityStore(identity_connection)
    else:
        identity_store = None
    job_connection = None
    if args.job_store:
        job_store: JobSubmissionStore | None = SQLiteJobStore(args.job_store)
    elif os.environ.get("DATABASE_URL"):
        try:
            import psycopg
        except ImportError as exc:
            raise SystemExit("install the postgres extra: pip install .[postgres]") from exc
        from .jobs_postgres import PostgresJobStore

        job_connection = psycopg.connect(os.environ["DATABASE_URL"])
        job_store = PostgresJobStore(job_connection)
    else:
        job_store = None
    ha_connection = None
    oidc_session_repository = None
    rate_limiter = None
    if os.environ.get("DATABASE_URL"):
        try:
            import psycopg
        except ImportError as exc:
            raise SystemExit("install the postgres extra: pip install .[postgres]") from exc
        ha_connection = psycopg.connect(os.environ["DATABASE_URL"])
        rate_limiter = PostgresRateLimiter(ha_connection, limit=args.rate_limit)
        if oidc_auth_client is not None:
            oidc_session_repository = PostgresOIDCSessionRepository(ha_connection)
    server = create_server(
        service,
        job_store=job_store,
        cors_origins=[o.strip() for o in args.cors_origins.split(",")],
        bearer_token=bearer_token,
        oidc_validator=oidc_validator,
        oidc_only=oidc_only,
        oidc_auth_client=oidc_auth_client,
        oidc_cookie_secure=not getattr(args, "oidc_cookie_insecure", False),
        oidc_session_repository=oidc_session_repository,
        operator_token=args.operator_token,
        operator_role=args.operator_role,
        operator_key_store=operator_key_store,
        identity_store=identity_store,
        host=args.host,
        port=args.port,
        max_body_bytes=args.max_body_bytes,
        rate_limit=args.rate_limit,
        rate_limiter=rate_limiter,
    )
    print(f"Serving Governed Autonomy HTTP API on http://{args.host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if operator_key_store is not None:
            operator_key_store.close()
        if isinstance(identity_store, SQLiteIdentityStore):
            identity_store.close()
        if identity_connection is not None:
            identity_connection.close()
        if job_store is not None:
            if isinstance(job_store, SQLiteJobStore):
                job_store.close()
            elif job_connection is not None:
                job_connection.close()
        if ha_connection is not None:
            ha_connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


API_SCHEMA = {
    "openapi": "3.0.3",
    "info": {
        "title": "Governed Autonomy Substrate",
        "version": "1.0",
        "description": "Authenticated authorization, execution, health, and audit APIs.",
    },
    "servers": [{"url": "/"}],
    "components": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer"},
        },
        "schemas": {
            "AuthorizeRequest": {
                "type": "object",
                "required": ["policy_id", "request"],
                "properties": {
                    "policy_id": {"type": "string"},
                    "request": {"type": "object", "additionalProperties": True},
                    "ttl_seconds": {"type": "integer", "minimum": 1},
                    "approvals": {"type": "array", "items": {"type": "object"}},
                    "mesh_inputs": {"type": "array", "items": {"type": "object"}},
                },
            },
            "ExecuteRequest": {
                "type": "object",
                "required": ["artifact"],
                "properties": {"artifact": {"type": "object", "additionalProperties": True}},
            },
            "Error": {
                "type": "object",
                "required": ["error"],
                "properties": {"error": {"type": "string"}, "decision": {"type": "object"}},
            },
            "AuthorizationArtifact": {
                "type": "object",
                "description": "Signed governance authorization artifact (GAA)",
                "additionalProperties": True,
            },
            "ExecuteResponse": {
                "type": "object",
                "required": ["result"],
                "properties": {"result": {"type": "object", "additionalProperties": True}},
            },
            "HealthReport": {
                "type": "object",
                "required": ["ok"],
                "properties": {"ok": {"type": "boolean"}, "status": {"type": "string"}},
                "additionalProperties": True,
            },
            "JobSubmission": {
                "type": "object",
                "required": ["artifact", "idempotency_key"],
                "properties": {
                    "artifact": {
                        "oneOf": [
                            {"type": "object", "additionalProperties": True},
                            {"type": "string", "description": "Serialized GAA JSON"},
                        ]
                    },
                    "idempotency_key": {"type": "string", "minLength": 1},
                    "max_attempts": {"type": "integer", "minimum": 1, "maximum": 20},
                },
            },
        },
    },
    "paths": {
        "/api/v1/authorize": {
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/AuthorizeRequest"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Signed governance authorization artifact",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AuthorizationArtifact"}
                            }
                        },
                    },
                    "400": {
                        "description": "Invalid request",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}
                        },
                    },
                    "401": {
                        "description": "Unauthorized",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}
                        },
                    },
                    "403": {
                        "description": "Policy denied",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}
                        },
                    },
                },
            }
        },
        "/api/v1/execute": {
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/ExecuteRequest"}
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Action result",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ExecuteResponse"}
                            }
                        },
                    },
                    "400": {
                        "description": "Invalid request",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}
                        },
                    },
                    "401": {
                        "description": "Unauthorized",
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Error"}}
                        },
                    },
                },
            }
        },
        "/health": {
            "get": {
                "responses": {
                    "200": {
                        "description": "Health report",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthReport"}
                            }
                        },
                    }
                }
            }
        },
        "/readyz": {
            "get": {
                "responses": {
                    "200": {
                        "description": "Readiness report",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthReport"}
                            }
                        },
                    },
                    "503": {
                        "description": "Not ready",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthReport"}
                            }
                        },
                    },
                }
            }
        },
        "/livez": {
            "get": {
                "responses": {
                    "200": {
                        "description": "Liveness report",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthReport"}
                            }
                        },
                    }
                }
            }
        },
        "/startupz": {
            "get": {
                "responses": {
                    "200": {
                        "description": "Startup report",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/HealthReport"}
                            }
                        },
                    }
                }
            }
        },
        "/audit": {"get": {"responses": {"200": {"description": "Audit summary"}}}},
        "/admin/jobs": {
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/JobSubmission"}
                        }
                    },
                },
                "responses": {
                    "202": {"description": "Job accepted into the configured queue"},
                    "503": {"description": "Job queue is not configured or unavailable"},
                },
            }
        },
        "/admin/jobs/{job_id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "job_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "Job status"},
                    "404": {"description": "Job not found"},
                    "503": {"description": "Job queue is not configured or unavailable"},
                },
            }
        },
        "/openapi.json": {"get": {"responses": {"200": {"description": "OpenAPI document"}}}},
        "/auth/login": {
            "get": {
                "parameters": [
                    {
                        "name": "next",
                        "in": "query",
                        "required": False,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"302": {"description": "Redirect to the discovered OpenID provider"}},
            }
        },
        "/auth/callback": {
            "get": {
                "responses": {
                    "302": {"description": "Validated sign-in; sets browser session cookie"},
                    "400": {"description": "Invalid callback state"},
                    "401": {"description": "Sign-in token validation failed"},
                }
            }
        },
        "/auth/logout": {
            "post": {"responses": {"204": {"description": "Local browser session revoked"}}}
        },
        "/auth/me": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": (
                            "Authenticated subject, tenant, issuer, assigned roles, and identity type"
                        )
                    },
                    "401": {"description": "Authenticated OIDC identity required"},
                },
            }
        },
        "/admin": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Governance admin dashboard (HTML)"}},
            }
        },
        "/admin/app.js": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Admin dashboard client-side script"}},
            }
        },
        "/admin/app.css": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Admin dashboard stylesheet"}},
            }
        },
        "/admin/policies": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Registered policies"}},
            }
        },
        "/admin/metrics": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Runtime metrics"}},
            }
        },
        "/admin/control-room": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": (
                            "Authenticated mission-control snapshot of inventory, policies, "
                            "approvals, replay incidents, timeline, and analytics"
                        )
                    }
                },
            }
        },
        "/admin/trust": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Trusted signing keys snapshot"}},
            }
        },
        "/admin/operator-keys": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Operator API keys (secrets omitted)"}},
            },
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["operator_id"],
                                "properties": {"operator_id": {"type": "string"}},
                            }
                        }
                    },
                },
                "/admin/identities/role-assignments": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "Explicit role assignments"}},
                    },
                    "post": {
                        "security": [{"bearerAuth": []}],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["principal_id", "role"],
                                        "properties": {
                                            "principal_id": {"type": "string"},
                                            "role": {
                                                "type": "string",
                                                "enum": sorted(role.value for role in Role),
                                            },
                                        },
                                    }
                                }
                            },
                        },
                        "responses": {"201": {"description": "Role assignment recorded"}},
                    },
                },
                "/admin/identities/service-principals": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "Authenticated service principals"}},
                    }
                },
                "/admin/identities/events": {
                    "get": {
                        "security": [{"bearerAuth": []}],
                        "responses": {
                            "200": {"description": "Identity and role-assignment events"}
                        },
                    }
                },
                "responses": {
                    "201": {
                        "description": (
                            "Created operator key; bearer token is returned once and is not stored"
                        )
                    }
                },
            },
        },
        "/admin/operator-keys/{key_id}/revoke": {
            "post": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Operator API key revoked"}},
            }
        },
        "/admin/governance-log": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {
                        "description": (
                            "Durable, hash-chained history of policy/trust governance "
                            "events (proposed, approved, activated, key_added, key_revoked)"
                        )
                    }
                },
            }
        },
        "/admin/proposals": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "Policy change proposals"}},
            },
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Submit a proposal signed externally with the payload from /admin/proposals/prepare.",
                "responses": {"201": {"description": "Created proposal summary"}},
            },
        },
        "/admin/proposals/prepare": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Return the exact bytes a proposer must sign.",
                "responses": {"200": {"description": "Unsigned proposal payload"}},
            }
        },
        "/admin/proposals/{proposal_id}/prepare-approval": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Return the exact bytes an approver must sign.",
                "responses": {"200": {"description": "Unsigned approval payload"}},
            }
        },
        "/admin/proposals/{proposal_id}/approve": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Submit an approval signed externally with the payload from prepare-approval.",
                "responses": {"200": {"description": "Updated proposal summary"}},
            }
        },
        "/admin/proposals/{proposal_id}/activate": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Activate a proposal that has met its approval quorum.",
                "responses": {"200": {"description": "Activated policy summary"}},
            }
        },
        "/admin/trust/keys/prepare": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Return the exact bytes an existing trusted key must sign to add a new trusted key.",
                "responses": {"200": {"description": "Unsigned trust-add payload"}},
            }
        },
        "/admin/trust/keys": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Add a trusted key, signed externally by an existing trusted key.",
                "responses": {"201": {"description": "Updated trust store snapshot"}},
            }
        },
        "/admin/trust/keys/{key_id}/revoke/prepare": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Return the exact bytes an existing trusted key must sign to revoke a trusted key.",
                "responses": {"200": {"description": "Unsigned trust-revoke payload"}},
            }
        },
        "/admin/trust/keys/{key_id}/revoke": {
            "post": {
                "security": [{"bearerAuth": []}],
                "description": "Revoke a trusted key, signed externally by an existing trusted key.",
                "responses": {"200": {"description": "Updated trust store snapshot"}},
            }
        },
    },
}


def _complete_schema(schema: dict[str, Any]) -> None:
    """Add JSON body schemas and auth error responses to every documented operation."""
    json_ref = lambda name: {  # noqa: E731
        "application/json": {"schema": {"$ref": f"#/components/schemas/{name}"}}
    }
    schemas = schema["components"]["schemas"]
    schemas.setdefault("Object", {"type": "object", "additionalProperties": True})
    for path, operations in list(schema["paths"].items()):
        for operation in operations.values():
            responses = operation["responses"]
            for status, response in responses.items():
                if (
                    status.startswith("2")
                    and "content" not in response
                    and not path.startswith("/admin/app.")
                    and path != "/admin"
                ):
                    response["content"] = json_ref("Object")
                elif status.startswith(("4", "5")) and "content" not in response:
                    response["content"] = json_ref("Error")
            if operation.get("security"):
                for status, text in (("401", "Unauthorized"), ("403", "Forbidden")):
                    responses.setdefault(
                        status, {"description": text, "content": json_ref("Error")}
                    )
    for path in ("/health", "/livez", "/readyz", "/startupz", "/audit", "/openapi.json"):
        schema["paths"].setdefault(f"/api/v1{path}", schema["paths"][path])


_complete_schema(API_SCHEMA)
