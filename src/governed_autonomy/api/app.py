from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse

from ..bootstrap import build_platform_demo, build_runtime_service
from ..canonical import canonical_json
from ..control_plane import (
    ControlPlaneRepository,
    InMemoryControlPlaneRepository,
    PolicyVersionRecord,
    ServicePrincipalRecord,
    build_control_plane_repository,
    run_postgres_migrations,
    synchronize_policy_registry,
    synchronize_principal_registry,
)
from ..deployment import correlation_id
from ..errors import AuthorizationError
from ..health import health_report
from ..identity import IdentityValidationError, OIDCValidator, UrlJWKSProvider
from ..issuer import PolicyDeniedError
from ..mesh import GovernanceInput
from ..platform import GovernancePlatform, RuntimeIdentity, ServicePrincipalRegistry
from .models import (
    ApprovalDecisionRequest,
    AuthorizeRequest,
    ExecuteRequest,
    PolicyPublishRequest,
    PolicyUpsertRequest,
    PrincipalRevokeRequest,
    PrincipalUpsertRequest,
    TenantCreateRequest,
)


@dataclass(frozen=True)
class AuthContext:
    subject: str | None = None
    tenant_id: str | None = None
    roles: tuple[str, ...] = ()
    principal_id: str | None = None


@dataclass(frozen=True)
class AppContext:
    platform: GovernancePlatform
    control_plane: ControlPlaneRepository
    principal_registry: ServicePrincipalRegistry


def _safe_detail(detail: str) -> str:
    return detail.replace("\n", " ").replace("\r", " ").strip()[:256]


def _problem(request: Request, status_code: int, title: str, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "type": "about:blank",
            "title": title,
            "status": status_code,
            "detail": _safe_detail(detail),
            "request_id": request.state.request_id,
        },
        headers={"X-Request-ID": request.state.request_id},
    )


def _public_error_detail(value: object, fallback: str) -> str:
    if isinstance(value, str) and value and "\n" not in value and "\r" not in value:
        return value[:256]
    return fallback


def _authorization_response(record, repository: ControlPlaneRepository) -> dict[str, Any]:
    return {
        "authorization_id": record.authorization_id,
        "policy_id": record.policy_id,
        "status": record.status,
        "artifact": record.artifact_payload,
        "result": record.result_payload,
        "error": record.error_text,
        "approvals_count": record.approvals_count,
        "required_approvals": record.required_approvals,
        "approvals": [
            {
                "decision": item.decision,
                "actor_id": item.actor_id,
                "rationale": item.rationale,
                "created_at": item.created_at,
            }
            for item in repository.list_approvals(record.authorization_id)
        ],
    }


def _policy_response(record: PolicyVersionRecord) -> dict[str, Any]:
    return {
        "policy_id": record.policy_id,
        "version": record.version,
        "published": record.published,
        "policy": record.policy.to_dict(),
    }


def _principal_response(record: ServicePrincipalRecord) -> dict[str, Any]:
    return {
        "principal_id": record.principal_id,
        "tenant_id": record.tenant_id,
        "roles": list(record.roles),
        "allowed_actions": list(record.allowed_actions),
        "allowed_environments": list(record.allowed_environments),
        "allowed_sources": list(record.allowed_sources),
        "scope": record.scope or {},
        "public_key": record.public_key,
        "key_status": record.key_status,
    }


def _request_platform(base: GovernancePlatform, request: Request, auth: AuthContext) -> GovernancePlatform:
    roles = tuple(auth.roles)
    actor_id = request.headers.get("X-Actor-ID") or auth.subject
    tenant_id = request.headers.get("X-Tenant-ID") or auth.tenant_id or base.identity.tenant_id
    principal_id = request.headers.get("X-Principal-ID") or auth.principal_id or base.identity.principal_id
    identity = replace(
        base.identity,
        actor_id=actor_id,
        tenant_id=tenant_id,
        principal_id=principal_id,
        roles=roles or base.identity.roles,
        request_id=request.state.request_id,
        source="api",
    )
    return GovernancePlatform(
        service=base.service,
        identity=identity,
        deployment_policy=base.deployment_policy,
        principal_registry=(
            base.principal_registry
            if base.principal_registry is not None
            and bool(getattr(base.principal_registry, "_principals", {}))
            else None
        ),
        mesh_source_registry=base.mesh_source_registry,
    )


def _build_default_context() -> AppContext:
    mode = os.environ.get("GAS_RUNTIME_MODE", "postgres").lower()
    database_url = os.environ.get("DATABASE_URL") if mode == "postgres" else None
    control_plane_database_url = os.environ.get("GAS_CONTROL_PLANE_DATABASE_URL") or database_url
    if mode == "memory":
        platform, _, _, _ = build_platform_demo(
            service_name=os.environ.get("GAS_SERVICE_NAME", "governed-autonomy-api"),
            environment=os.environ.get("GAS_ENVIRONMENT", "dev"),
        )
        control_plane = (
            build_control_plane_repository(database_url=control_plane_database_url)
            if control_plane_database_url
            else InMemoryControlPlaneRepository()
        )
    else:
        service, _, _ = build_runtime_service()
        principal_registry = ServicePrincipalRegistry()
        platform = GovernancePlatform(
            service=service,
            identity=RuntimeIdentity(
                service=os.environ.get("GAS_SERVICE_NAME", "governed-autonomy-api"),
                environment=os.environ.get("GAS_ENVIRONMENT", "prod"),
            ),
            principal_registry=principal_registry,
        )
        if database_url is None:
            raise RuntimeError("DATABASE_URL is required for postgres runtime mode")
        if control_plane_database_url is None:
            raise RuntimeError("DATABASE_URL is required for postgres runtime mode")
        control_plane = build_control_plane_repository(database_url=control_plane_database_url)
        with suppress(AttributeError):
            run_postgres_migrations(control_plane.connection)  # type: ignore[attr-defined]
    principal_registry = platform.principal_registry or ServicePrincipalRegistry()
    if not control_plane.list_policies():
        for policy in platform.service.policies.policies():
            control_plane.save_policy(policy, published=True)
    synchronize_policy_registry(platform.service.policies, control_plane)
    synchronize_principal_registry(principal_registry, control_plane)
    return AppContext(
        platform=platform,
        control_plane=control_plane,
        principal_registry=principal_registry,
    )


def _auth_dependency(
    *,
    bearer_token: str | None,
    oidc_validator: OIDCValidator | None,
    auth_dependency: Callable[[Request], AuthContext] | None,
):
    async def dependency(request: Request) -> AuthContext:
        if auth_dependency is not None:
            return auth_dependency(request)
        supplied = request.headers.get("Authorization", "")
        if oidc_validator is not None:
            if not supplied.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="missing bearer token")
            try:
                identity = oidc_validator.validate_token(supplied[7:].strip())
            except IdentityValidationError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc
            roles = identity.claims.get("roles", [])
            if isinstance(roles, str):
                roles = [roles]
            tenant_id = identity.claims.get("tenant_id") or identity.claims.get("tenant")
            principal_id = identity.claims.get("principal_id")
            return AuthContext(
                subject=identity.subject,
                tenant_id=tenant_id if isinstance(tenant_id, str) else None,
                roles=tuple(str(role) for role in roles),
                principal_id=principal_id if isinstance(principal_id, str) else None,
            )
        if bearer_token is None:
            return AuthContext(subject=request.headers.get("X-Actor-ID"))
        if not hmac.compare_digest(supplied, "Bearer " + bearer_token):
            raise HTTPException(status_code=401, detail="unauthorized")
        return AuthContext(subject=request.headers.get("X-Actor-ID"))

    return dependency


def create_app(
    *,
    platform: GovernancePlatform | None = None,
    control_plane: ControlPlaneRepository | None = None,
    bearer_token: str | None = None,
    oidc_validator: OIDCValidator | None = None,
    auth_dependency: Callable[[Request], AuthContext] | None = None,
) -> FastAPI:
    app = FastAPI(
        title="Governed Autonomy Platform",
        version="1.0",
        openapi_url="/v1/openapi.json",
        docs_url="/v1/docs",
    )
    context = (
        AppContext(
            platform=platform,
            control_plane=control_plane,
            principal_registry=platform.principal_registry or ServicePrincipalRegistry(),
        )
        if platform is not None and control_plane is not None
        else _build_default_context()
    )
    synchronize_policy_registry(context.platform.service.policies, context.control_plane)
    synchronize_principal_registry(context.principal_registry, context.control_plane)
    app.state.context = context
    auth = _auth_dependency(
        bearer_token=bearer_token,
        oidc_validator=oidc_validator,
        auth_dependency=auth_dependency,
    )

    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        request.state.request_id = correlation_id(request.headers.get("X-Request-ID"))
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        detail = _public_error_detail(exc.detail, "request failed")
        return _problem(request, exc.status_code, "request failed", detail)

    @app.exception_handler(KeyError)
    async def key_error_handler(request: Request, _exc: KeyError):
        return _problem(request, status.HTTP_404_NOT_FOUND, "not found", "resource not found")

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, _exc: ValueError):
        return _problem(
            request,
            status.HTTP_400_BAD_REQUEST,
            "invalid request",
            "request payload is invalid",
        )

    def current_context() -> AppContext:
        return app.state.context

    @app.get("/v1/health")
    def v1_health(ctx: AppContext = Depends(current_context), _auth: AuthContext = Depends(auth)):
        return health_report(
            replay_log=ctx.platform.service.boundary.replay_log,
            trust_store=ctx.platform.service.boundary.trust_store,
            policy_registry=ctx.platform.service.policies,
            mesh_source_registry=ctx.platform.service.mesh_source_registry,
        )

    @app.get("/v1/ready")
    def v1_ready(request: Request, ctx: AppContext = Depends(current_context), _auth: AuthContext = Depends(auth)):
        report = health_report(
            replay_log=ctx.platform.service.boundary.replay_log,
            trust_store=ctx.platform.service.boundary.trust_store,
            policy_registry=ctx.platform.service.policies,
            mesh_source_registry=ctx.platform.service.mesh_source_registry,
        )
        if not report["ok"]:
            return _problem(request, status.HTTP_503_SERVICE_UNAVAILABLE, "not ready", "service is not ready")
        return report

    @app.get("/v1/policies")
    def list_policies(ctx: AppContext = Depends(current_context), _auth: AuthContext = Depends(auth)):
        return {"policies": [_policy_response(record) for record in ctx.control_plane.list_policies()]}

    @app.post("/v1/policies", status_code=201)
    def create_policy(
        body: PolicyUpsertRequest,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        record = ctx.control_plane.save_policy(body.to_policy())
        return _policy_response(record)

    @app.put("/v1/policies/{policy_id}")
    def update_policy(
        policy_id: str,
        body: PolicyUpsertRequest,
        request: Request,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        policy = body.to_policy()
        if policy.policy_id != policy_id:
            return _problem(request, status.HTTP_400_BAD_REQUEST, "invalid request", "policy_id path mismatch")
        record = ctx.control_plane.save_policy(policy)
        return _policy_response(record)

    @app.post("/v1/policies/{policy_id}/publish")
    def publish_policy(
        policy_id: str,
        body: PolicyPublishRequest,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        record = ctx.control_plane.publish_policy(policy_id, version=body.version)
        synchronize_policy_registry(ctx.platform.service.policies, ctx.control_plane)
        return _policy_response(record)

    @app.get("/v1/principals")
    def list_principals(ctx: AppContext = Depends(current_context), _auth: AuthContext = Depends(auth)):
        return {"principals": [_principal_response(record) for record in ctx.control_plane.list_principals()]}

    @app.post("/v1/principals", status_code=201)
    def create_principal(
        body: PrincipalUpsertRequest,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        record = ctx.control_plane.register_principal(
            ServicePrincipalRecord(
                principal_id=body.principal_id,
                tenant_id=body.tenant_id,
                roles=tuple(body.roles),
                allowed_actions=tuple(body.allowed_actions),
                allowed_environments=tuple(body.allowed_environments),
                allowed_sources=tuple(body.allowed_sources),
                scope=body.scope,
                public_key=body.public_key,
            )
        )
        synchronize_principal_registry(ctx.principal_registry, ctx.control_plane)
        return _principal_response(record)

    @app.post("/v1/principals/{principal_id}/revoke")
    def revoke_principal(
        principal_id: str,
        _body: PrincipalRevokeRequest,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        record = ctx.control_plane.revoke_principal(principal_id)
        synchronize_principal_registry(ctx.principal_registry, ctx.control_plane)
        return _principal_response(record)

    @app.post("/v1/tenants", status_code=201)
    def create_tenant(
        body: TenantCreateRequest,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        record = ctx.control_plane.create_tenant(body.tenant_id, name=body.name)
        return {
            "tenant_id": record.tenant_id,
            "name": record.name,
            "status": record.status,
        }

    @app.post("/v1/authorize")
    def authorize(
        body: AuthorizeRequest,
        request: Request,
        ctx: AppContext = Depends(current_context),
        caller: AuthContext = Depends(auth),
    ):
        request_digest = hashlib.sha256(
            canonical_json(
                {
                    "policy_id": body.policy_id,
                    "request": body.request,
                    "context": body.context,
                    "mesh_inputs": body.mesh_inputs,
                    "ttl_seconds": body.ttl_seconds,
                }
            )
        ).hexdigest()
        idempotency_key = request.headers.get("Idempotency-Key")
        if idempotency_key is not None:
            existing = ctx.control_plane.get_authorization_by_idempotency_key(idempotency_key)
            if existing is not None:
                if existing.request_digest != request_digest:
                    return _problem(
                        request,
                        status.HTTP_409_CONFLICT,
                        "idempotency conflict",
                        "Idempotency-Key was already used for a different request",
                    )
                return _authorization_response(existing, ctx.control_plane)
        policy = ctx.platform.service.policies.get(body.policy_id)
        if policy is None:
            raise KeyError(f"unknown policy: {body.policy_id}")
        required_approvals = policy.required_approvals.get(str(body.request.get("action")), 0)
        runtime_platform = _request_platform(ctx.platform, request, caller)
        record = ctx.control_plane.create_authorization(
            policy_id=body.policy_id,
            request_payload=body.request,
            context=body.context,
            mesh_inputs=body.mesh_inputs,
            request_digest=request_digest,
            idempotency_key=idempotency_key,
            ttl_seconds=body.ttl_seconds,
            required_approvals=required_approvals,
            max_attempts=body.max_attempts,
        )
        approvals = list(body.approvals)
        if required_approvals > 0 and not approvals:
            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content=_authorization_response(record, ctx.control_plane),
                headers={"X-Request-ID": request.state.request_id},
            )
        try:
            artifact = runtime_platform.authorize(
                dict(body.request),
                body.policy_id,
                ttl_seconds=body.ttl_seconds,
                approvals=approvals or None,
                context=dict(body.context),
                mesh_inputs=[GovernanceInput.from_dict(item) for item in body.mesh_inputs],
            )
        except PolicyDeniedError as exc:
            ctx.control_plane.update_authorization(
                record.authorization_id,
                status="failed",
                error_text=str(exc),
            )
            return _problem(
                request,
                status.HTTP_403_FORBIDDEN,
                "policy denied",
                "request violates policy",
            )
        updated = ctx.control_plane.update_authorization(
            record.authorization_id,
            status="authorized",
            artifact_payload=artifact.to_dict(),
            expires_at=artifact.expires_at,
        )
        return _authorization_response(updated, ctx.control_plane)

    @app.get("/v1/authorizations/{authorization_id}")
    def get_authorization(
        authorization_id: str,
        ctx: AppContext = Depends(current_context),
        _auth: AuthContext = Depends(auth),
    ):
        return _authorization_response(ctx.control_plane.get_authorization(authorization_id), ctx.control_plane)

    @app.post("/v1/authorizations/{authorization_id}/approve")
    def approve_authorization(
        authorization_id: str,
        body: ApprovalDecisionRequest,
        request: Request,
        ctx: AppContext = Depends(current_context),
        caller: AuthContext = Depends(auth),
    ):
        ctx.control_plane.record_approval(
            authorization_id,
            decision="approve",
            actor_id=body.actor_id or caller.subject,
            rationale=body.rationale,
        )
        record = ctx.control_plane.get_authorization(authorization_id)
        if record.status == "cancelled" or record.status == "failed":
            return _authorization_response(record, ctx.control_plane)
        if record.status == "authorized" or record.approvals_count < record.required_approvals:
            return _authorization_response(record, ctx.control_plane)
        if record.status != "awaiting_approval":
            return _authorization_response(record, ctx.control_plane)
        runtime_platform = _request_platform(ctx.platform, request, caller)
        context_payload = dict(record.context)
        context_payload["approval_count"] = record.approvals_count
        artifact = runtime_platform.authorize(
            dict(record.request_payload),
            record.policy_id,
            ttl_seconds=record.ttl_seconds,
            context=context_payload,
            mesh_inputs=[GovernanceInput.from_dict(item) for item in record.mesh_inputs],
        )
        updated = ctx.control_plane.update_authorization(
            authorization_id,
            status="authorized",
            artifact_payload=artifact.to_dict(),
            expires_at=artifact.expires_at,
        )
        return _authorization_response(updated, ctx.control_plane)

    @app.post("/v1/authorizations/{authorization_id}/deny")
    def deny_authorization(
        authorization_id: str,
        body: ApprovalDecisionRequest,
        ctx: AppContext = Depends(current_context),
        caller: AuthContext = Depends(auth),
    ):
        ctx.control_plane.record_approval(
            authorization_id,
            decision="deny",
            actor_id=body.actor_id or caller.subject,
            rationale=body.rationale,
        )
        record = ctx.control_plane.update_authorization(
            authorization_id,
            status="cancelled",
            error_text=body.rationale or "authorization denied",
        )
        return _authorization_response(record, ctx.control_plane)

    @app.post("/v1/execute")
    def execute(
        body: ExecuteRequest,
        request: Request,
        ctx: AppContext = Depends(current_context),
        caller: AuthContext = Depends(auth),
    ):
        record = ctx.control_plane.get_authorization(body.authorization_id)
        artifact = record.artifact()
        if artifact is None:
            return _problem(
                request,
                status.HTTP_409_CONFLICT,
                "execution unavailable",
                "authorization does not have an executable artifact",
            )
        runtime_platform = _request_platform(ctx.platform, request, caller)
        try:
            result = runtime_platform.execute(artifact)
        except AuthorizationError as exc:
            updated = ctx.control_plane.update_authorization(
                body.authorization_id,
                status="failed",
                error_text=str(exc),
            )
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content=_authorization_response(updated, ctx.control_plane),
                headers={"X-Request-ID": request.state.request_id},
            )
        updated = ctx.control_plane.update_authorization(
            body.authorization_id,
            status="executed",
            result_payload=result,
            error_text=None,
        )
        return _authorization_response(updated, ctx.control_plane)

    @app.get("/v1/audit/events")
    def audit_events(ctx: AppContext = Depends(current_context), _auth: AuthContext = Depends(auth)):
        return {"events": list(ctx.platform.service.boundary.replay_log.events())}

    @app.get("/v1/audit/reports")
    def audit_reports(ctx: AppContext = Depends(current_context), _auth: AuthContext = Depends(auth)):
        replay_log = ctx.platform.service.boundary.replay_log
        return {
            "audit_summary": replay_log.audit_summary(),
            "verify_chain": replay_log.verify_chain(),
            "integrity": replay_log.verify_integrity(),
        }

    return app


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Governed Autonomy Platform API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bearer-token", default=os.environ.get("GOVERNED_AUTONOMY_BEARER_TOKEN"))
    parser.add_argument("--oidc-issuer", default=os.environ.get("OIDC_ISSUER"))
    parser.add_argument("--oidc-audience", default=os.environ.get("OIDC_AUDIENCE"))
    parser.add_argument("--oidc-jwks-url", default=os.environ.get("OIDC_JWKS_URL"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        import uvicorn
    except ImportError as exc:  # pragma: no cover - runtime dependency
        raise SystemExit("install uvicorn to run the FastAPI service") from exc
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
    uvicorn.run(
        create_app(bearer_token=args.bearer_token, oidc_validator=oidc_validator),
        host=args.host,
        port=args.port,
    )
    return 0
