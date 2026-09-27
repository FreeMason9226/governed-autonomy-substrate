from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from ..api.app import _build_default_context
from ..control_plane import (
    run_postgres_migrations,
    synchronize_policy_registry,
    synchronize_principal_registry,
)
from ..control_plane.repository import ServicePrincipalRecord
from ..policy import policy_from_dict


def _load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gas", description="Governed Autonomy platform CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    tenant = subparsers.add_parser("tenant")
    tenant_sub = tenant.add_subparsers(dest="tenant_command", required=True)
    tenant_create = tenant_sub.add_parser("create")
    tenant_create.add_argument("tenant_id")
    tenant_create.add_argument("--name")

    principal = subparsers.add_parser("principal")
    principal_sub = principal.add_subparsers(dest="principal_command", required=True)
    principal_register = principal_sub.add_parser("register")
    principal_register.add_argument("file")
    principal_revoke = principal_sub.add_parser("revoke")
    principal_revoke.add_argument("principal_id")

    policy = subparsers.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_publish = policy_sub.add_parser("publish")
    policy_publish.add_argument("file")

    authorization = subparsers.add_parser("authorization")
    authorization_sub = authorization.add_subparsers(dest="authorization_command", required=True)
    authorization_inspect = authorization_sub.add_parser("inspect")
    authorization_inspect.add_argument("authorization_id")

    migrate = subparsers.add_parser("migrate")
    migrate.add_argument("--database-url", default=os.environ.get("DATABASE_URL"))

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "migrate":
        if not args.database_url:
            raise SystemExit("DATABASE_URL or --database-url is required")
        import psycopg

        connection = psycopg.connect(args.database_url)
        try:
            applied = run_postgres_migrations(connection)
        finally:
            connection.close()
        print(json.dumps({"applied": applied}, sort_keys=True))
        return 0

    context = _build_default_context()
    if args.command == "tenant" and args.tenant_command == "create":
        record = context.control_plane.create_tenant(args.tenant_id, name=args.name)
        print(json.dumps({"tenant_id": record.tenant_id, "name": record.name, "status": record.status}, sort_keys=True))
        return 0

    if args.command == "principal" and args.principal_command == "register":
        payload = _load_json(args.file)
        record = context.control_plane.register_principal(
            ServicePrincipalRecord(
                principal_id=payload["principal_id"],
                tenant_id=payload.get("tenant_id"),
                roles=tuple(payload.get("roles", [])),
                allowed_actions=tuple(payload.get("allowed_actions", [])),
                allowed_environments=tuple(payload.get("allowed_environments", [])),
                allowed_sources=tuple(payload.get("allowed_sources", [])),
                scope=payload.get("scope", {}),
                public_key=payload.get("public_key"),
            )
        )
        synchronize_principal_registry(context.principal_registry, context.control_plane)
        print(json.dumps({"principal_id": record.principal_id, "status": record.key_status}, sort_keys=True))
        return 0

    if args.command == "principal" and args.principal_command == "revoke":
        record = context.control_plane.revoke_principal(args.principal_id)
        synchronize_principal_registry(context.principal_registry, context.control_plane)
        print(json.dumps({"principal_id": record.principal_id, "status": record.key_status}, sort_keys=True))
        return 0

    if args.command == "policy" and args.policy_command == "publish":
        payload = _load_json(args.file)
        record = context.control_plane.save_policy(policy_from_dict(payload["policy"]))
        published = context.control_plane.publish_policy(record.policy_id, version=record.version)
        synchronize_policy_registry(context.platform.service.policies, context.control_plane)
        print(json.dumps({"policy_id": published.policy_id, "version": published.version, "published": published.published}, sort_keys=True))
        return 0

    if args.command == "authorization" and args.authorization_command == "inspect":
        record = context.control_plane.get_authorization(args.authorization_id)
        print(json.dumps({
            "authorization_id": record.authorization_id,
            "policy_id": record.policy_id,
            "status": record.status,
            "approvals_count": record.approvals_count,
            "required_approvals": record.required_approvals,
        }, sort_keys=True))
        return 0

    raise SystemExit("unsupported command")
