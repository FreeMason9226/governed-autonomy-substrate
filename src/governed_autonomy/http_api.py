import argparse
import hmac
import json
import os
import ssl
from collections.abc import Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .admin_ui import render_admin_ui
from .bootstrap import build_runtime_service
from .deployment import BoundedRateLimiter, TLSConfig, correlation_id, security_headers
from .errors import AuthorizationError
from .health import health_report
from .identity import IdentityValidationError, OIDCValidator, UrlJWKSProvider
from .issuer import PolicyDeniedError
from .mesh import GovernanceInput
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
        max_body_bytes: int = 64 * 1024,
        rate_limit: int = 120,
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
        self.max_body_bytes = max_body_bytes
        self.rate_limiter = BoundedRateLimiter(rate_limit)

    def handler(self) -> type[BaseHTTPRequestHandler]:
        api = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "GovernedAutonomy/0.2"

            def do_GET(self) -> None:
                if not api._allowed(self):
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
                    return
                if not api._authenticated(self):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                if self.path.startswith("/admin") and not api._operator_authorized(self):
                    self._send(
                        HTTPStatus.FORBIDDEN,
                        {"error": "operator authorization required"},
                    )
                    return
                if self.path == "/admin":
                    body = render_admin_ui()
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    for k, v in security_headers().items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if self.path in {"/health", "/livez", "/readyz", "/startupz"}:
                    report = health_report(
                        replay_log=api.service.boundary.replay_log,
                        trust_store=api.service.boundary.trust_store,
                        policy_registry=api.service.policies,
                        mesh_source_registry=api.service.mesh_source_registry,
                    )
                    if self.path == "/livez":
                        report = {"ok": True, "status": "live"}
                    elif self.path == "/startupz":
                        report = {"ok": True, "status": "started"}
                    elif self.path == "/readyz" and not report["ok"]:
                        self._send(HTTPStatus.SERVICE_UNAVAILABLE, report)
                        return
                    self._send(HTTPStatus.OK, report)
                    return
                if self.path == "/audit":
                    self._send(HTTPStatus.OK, api.service.audit_report())
                    return
                if self.path == "/admin/policies":
                    self._send(HTTPStatus.OK, {"policies": api.service.policies.to_dict()})
                    return
                if self.path == "/admin/proposals":
                    self._send(HTTPStatus.OK, {"proposals": []})
                    return
                if self.path == "/admin/metrics":
                    self._send(HTTPStatus.OK, api.service.audit_report()["audit_summary"])
                    return
                if self.path == "/openapi.json":
                    self._send(HTTPStatus.OK, API_SCHEMA)
                    return
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

            def do_POST(self) -> None:
                if not api._allowed(self):
                    self._send(HTTPStatus.TOO_MANY_REQUESTS, {"error": "rate limit exceeded"})
                    return
                if not api._authenticated(self):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                    return
                try:
                    payload = api._read_json(self)
                    if self.path in {"/authorize", "/api/v1/authorize"}:
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
                    elif self.path in {"/execute", "/api/v1/execute"}:
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

            def log_message(self, *_: Any) -> None:
                return

            def _send(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
                encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("X-Request-ID", api._request_id(self))
                for k, v in security_headers().items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(encoded)

        return Handler

    def _authenticated(self, request: BaseHTTPRequestHandler) -> bool:
        supplied = request.headers.get("Authorization", "")
        if self.oidc_validator is not None and supplied.startswith("Bearer "):
            try:
                request.gas_identity = self.oidc_validator.validate(supplied[7:].strip())  # type: ignore[attr-defined]
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

    def _operator_authorized(self, request: BaseHTTPRequestHandler) -> bool:
        identity = getattr(request, "gas_identity", None)
        if identity is not None:
            roles = identity.claims.get("roles", [])
            if isinstance(roles, str):
                roles = [roles]
            scopes = identity.claims.get("scope", "")
            if isinstance(scopes, str):
                scopes = scopes.split()
            return self.operator_role in roles or "gas.admin" in scopes
        supplied = request.headers.get("Authorization", "")
        return self.operator_token is not None and hmac.compare_digest(
            supplied, f"Bearer {self.operator_token}"
        )

    def _allowed(self, request: BaseHTTPRequestHandler) -> bool:
        return self.rate_limiter.allow(request.client_address[0])

    @staticmethod
    def _request_id(request: BaseHTTPRequestHandler) -> str:
        return correlation_id(request.headers.get("X-Request-ID"))

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


def parse_server_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Governed Autonomy HTTP API server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bearer-token", default=os.environ.get("GOVERNED_AUTONOMY_BEARER_TOKEN"))
    parser.add_argument("--oidc-issuer", default=os.environ.get("OIDC_ISSUER"))
    parser.add_argument("--oidc-audience", default=os.environ.get("OIDC_AUDIENCE"))
    parser.add_argument("--oidc-jwks-url", default=os.environ.get("OIDC_JWKS_URL"))
    parser.add_argument(
        "--operator-token", default=os.environ.get("GOVERNED_AUTONOMY_OPERATOR_TOKEN")
    )
    parser.add_argument(
        "--operator-role", default=os.environ.get("OIDC_OPERATOR_ROLE", "gas-admin")
    )
    parser.add_argument("--max-body-bytes", type=int, default=64 * 1024)
    parser.add_argument("--rate-limit", type=int, default=120)
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
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port),
        AuthenticatedAPI(
            service,
            bearer_token=bearer_token,
            oidc_validator=oidc_validator,
            operator_token=operator_token,
            operator_role=operator_role,
            max_body_bytes=max_body_bytes,
            rate_limit=rate_limit,
        ).handler(),
    )
    if tls is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
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
    oidc_args = (args.oidc_issuer, args.oidc_audience, args.oidc_jwks_url)
    if any(oidc_args) and not all(oidc_args):
        raise SystemExit(
            "OIDC_ISSUER, OIDC_AUDIENCE, and OIDC_JWKS_URL must be configured together"
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
    server = create_server(
        service,
        bearer_token=args.bearer_token,
        oidc_validator=oidc_validator,
        operator_token=args.operator_token,
        operator_role=args.operator_role,
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


API_SCHEMA = {
    "openapi": "3.0.0",
    "info": {"title": "Governed Autonomy Substrate", "version": "1.0"},
    "paths": {
        "/api/v1/authorize": {"post": {"requestBody": {"required": True}}},
        "/api/v1/execute": {"post": {"requestBody": {"required": True}}},
        "/health": {"get": {}},
        "/readyz": {"get": {}},
    },
}
