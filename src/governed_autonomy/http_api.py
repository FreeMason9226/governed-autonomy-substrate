import argparse
import hmac
import json
import os
import re
import sqlite3
import ssl
import uuid
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from .admin_ui import render_admin_css, render_admin_js, render_admin_ui
from .bootstrap import build_runtime_service
from .deployment import BoundedRateLimiter, TLSConfig, security_headers
from .errors import AuthorizationError
from .health import health_report
from .identity import (
    IdentityValidationError,
    OIDCValidator,
    UrlJWKSProvider,
    oidc_validator_from_discovery,
)
from .issuer import PolicyDeniedError
from .jobs import JobStoreError, JobSubmissionStore, SQLiteJobStore
from .mesh import GovernanceInput
from .operator_auth import OperatorKeyStore
from .platform_admin import PolicyChangeManager, TrustChangeManager
from .policy import policy_from_dict
from .rbac import ClaimsMapper, Role, require_roles
from .service import GovernedService


class AuthenticatedAPI:
    def __init__(
        self,
        service: GovernedService,
        *,
        bearer_token: str | None = None,
        oidc_validator: OIDCValidator | None = None,
        operator_token: str | None = None,
        operator_role: str = "gas-admin",
        operator_key_store: OperatorKeyStore | None = None,
        job_store: JobSubmissionStore | None = None,
        max_body_bytes: int = 64 * 1024,
        rate_limit: int = 120,
        cors_origins: Sequence[str] = (),
    ) -> None:
        if not bearer_token and oidc_validator is None:
            raise ValueError("bearer_token or oidc_validator is required")
        if max_body_bytes <= 0:
            raise ValueError("positive max_body_bytes is required")
        self.service = service
        self.bearer_token = bearer_token
        self.oidc_validator = oidc_validator
        self.operator_token = operator_token
        self.operator_role = operator_role
        self.operator_key_store = operator_key_store
        self.job_store = job_store
        self.max_body_bytes = max_body_bytes
        self.cors_origins = frozenset(o.rstrip("/") for o in cors_origins if o)
        self.rate_limiter = BoundedRateLimiter(rate_limit)
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

            def _cors_headers(self) -> dict[str, str]:
                requested = (self.headers.get("Origin") or "").rstrip("/")
                if not re.fullmatch(r"[A-Za-z0-9.:/_-]{1,255}", requested):
                    return {}
                origin = next((o for o in api.cors_origins if o == requested), None)
                if not origin:
                    return {}
                return {
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Expose-Headers": "X-Request-ID",
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
                        "Access-Control-Allow-Headers", "Authorization, Content-Type"
                    )
                    self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
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
                if route.startswith("/admin") and not api._operator_authorized(self, write=False):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "operator authorization required"},
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
                if route.startswith("/admin/jobs/"):
                    self._handle_admin_job_get(route)
                    return
                if route == "/admin/governance-log":
                    self._send(HTTPStatus.OK, {"events": list(api.service.governance_log())})
                    return
                if route == "/admin/metrics":
                    self._send(HTTPStatus.OK, api.service.audit_report()["audit_summary"])
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
                if route.startswith("/admin") and not api._operator_authorized(self):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "operator authorization required"},
                    )
                    return
                if route.startswith("/admin/proposals"):
                    self._handle_admin_proposals_post(route)
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
                        result = api.service.authorize(
                            payload["request"],
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
                            api.submit_approval(
                                parts[0], payload, actor_id=api._actor_id(self)
                            ),
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
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE, {"error": "job store unavailable"}
                    )

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
                    self._send(
                        HTTPStatus.SERVICE_UNAVAILABLE, {"error": "job store unavailable"}
                    )
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
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("X-Request-ID", api._request_id(self))
                self._send_cors()
                for k, v in security_headers().items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(encoded)

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

    def _authenticated(self, request: BaseHTTPRequestHandler) -> bool:
        supplied = request.headers.get("Authorization", "")
        scheme, separator, credential = supplied.partition(" ")
        bearer_credential = credential.strip() if separator and scheme.lower() == "bearer" else ""
        if self.operator_key_store is not None and bearer_credential:
            operator_key = self.operator_key_store.authenticate(bearer_credential)
            if operator_key is not None:
                if not urlsplit(request.path).path.startswith("/admin"):
                    return False
                request.gas_operator_id = operator_key.operator_id  # type: ignore[attr-defined]
                request.gas_operator_key_id = operator_key.key_id  # type: ignore[attr-defined]
                return True
        if self.oidc_validator is not None and bearer_credential:
            try:
                request.gas_identity = self.oidc_validator.validate(bearer_credential)  # type: ignore[attr-defined]
            except IdentityValidationError:
                return False
            return True
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

    @staticmethod
    def _actor_id(request: BaseHTTPRequestHandler) -> str:
        operator_id = getattr(request, "gas_operator_id", None)
        if operator_id is not None:
            key_id = getattr(request, "gas_operator_key_id", None)
            return f"api-key:{operator_id}:{key_id}" if key_id else f"api-key:{operator_id}"
        identity = getattr(request, "gas_identity", None)
        if identity is not None:
            return f"oidc:{identity.issuer}:{identity.subject}"
        return "shared-token"

    def _operator_authorized(self, request: BaseHTTPRequestHandler, *, write: bool = True) -> bool:
        if getattr(request, "gas_operator_id", None) is not None:
            return True
        identity = getattr(request, "gas_identity", None)
        if identity is not None:
            mapper = ClaimsMapper(legacy_admin_role=self.operator_role)
            try:
                mapped = mapper.map_to_identity({**identity.claims, "sub": identity.subject})
                needed = [Role.OPERATOR] if write else [Role.OPERATOR, Role.AUDITOR]
                require_roles(mapped, needed)
            except (ValueError, PermissionError):
                return False
            return True
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

    def _require_operator_key_store(self) -> OperatorKeyStore:
        if self.operator_key_store is None:
            raise ValueError("operator API key management is not configured")
        return self.operator_key_store

    def list_operator_keys(self) -> dict[str, Any]:
        return {"keys": list(self._require_operator_key_store().list_keys())}

    def create_operator_key(
        self, payload: dict[str, Any], *, actor_id: str
    ) -> dict[str, str]:
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
        self.service.record_governance_event(
            "operator.key_revoked", key_id, actor_id=actor_id
        )


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
    bearer_token: str,
    host: str = "127.0.0.1",
    port: int = 0,
    max_body_bytes: int = 64 * 1024,
    rate_limit: int = 120,
    tls: TLSConfig | None = None,
    oidc_validator: OIDCValidator | None = None,
    operator_token: str | None = None,
    operator_role: str = "gas-admin",
    operator_key_store: OperatorKeyStore | None = None,
    job_store: JobSubmissionStore | None = None,
    cors_origins: Sequence[str] = (),
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port),
        AuthenticatedAPI(
            service,
            bearer_token=bearer_token,
            oidc_validator=oidc_validator,
            operator_token=operator_token,
            operator_role=operator_role,
            operator_key_store=operator_key_store,
            job_store=job_store,
            max_body_bytes=max_body_bytes,
            rate_limit=rate_limit,
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
    oidc_validator = None
    if args.oidc_discovery:
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
    if not args.bearer_token and oidc_validator is None:
        raise SystemExit(
            "GOVERNED_AUTONOMY_BEARER_TOKEN or complete OIDC configuration is required"
        )
    service, _, _ = build_runtime_service()
    operator_key_store = (
        OperatorKeyStore(args.operator_key_store) if args.operator_key_store else None
    )
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
    server = create_server(
        service,
        job_store=job_store,
        cors_origins=[o.strip() for o in args.cors_origins.split(",")],
        bearer_token=args.bearer_token,
        oidc_validator=oidc_validator,
        operator_token=args.operator_token,
        operator_role=args.operator_role,
        operator_key_store=operator_key_store,
        host=args.host,
        port=args.port,
        max_body_bytes=args.max_body_bytes,
        rate_limit=args.rate_limit,
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
        if job_store is not None:
            if isinstance(job_store, SQLiteJobStore):
                job_store.close()
            elif job_connection is not None:
                job_connection.close()
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
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AuthorizeRequest"}}},
                },
                "responses": {"200": {"description": "Signed governance authorization artifact"}},
            }
        },
        "/api/v1/execute": {
            "post": {
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ExecuteRequest"}}},
                },
                "responses": {"200": {"description": "Action result"}},
            }
        },
        "/health": {"get": {"responses": {"200": {"description": "Health report"}}}},
        "/readyz": {"get": {"responses": {"200": {"description": "Readiness report"}}}},
        "/livez": {"get": {"responses": {"200": {"description": "Liveness report"}}}},
        "/startupz": {"get": {"responses": {"200": {"description": "Startup report"}}}},
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
