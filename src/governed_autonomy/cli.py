"""``gas`` operator CLI: a thin, dependency-free client for the admin API.

Credentials live in ``$GAS_HOME`` (default ``~/.gas``) with owner-only permissions;
``GOVERNED_AUTONOMY_OPERATOR_TOKEN`` / ``GAS_API_URL`` override stored values.
Signed governance changes (policy/trust) stay in the admin dashboard, where
signing is performed client-side; this CLI never handles signing keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .auth.entra import EntraDeviceAuthorizationClient
from .identity import EntraOIDCConfig
from .replay import ReplayLog

DEFAULT_API_URL = "http://localhost:8000"


def config_path() -> Path:
    return Path(os.environ.get("GAS_HOME", Path.home() / ".gas")) / "credentials.json"


def load_credentials() -> dict[str, Any]:
    creds: dict[str, Any] = {
        "api_url": DEFAULT_API_URL,
        "token": None,  # nosec B105
        "tenant_id": None,
        "client_id": None,
        "scopes": None,
    }
    path = config_path()
    if path.exists():
        creds.update(json.loads(path.read_text(encoding="utf-8")))
    if os.environ.get("GAS_API_URL"):
        creds["api_url"] = os.environ["GAS_API_URL"]
    if os.environ.get("GOVERNED_AUTONOMY_OPERATOR_TOKEN"):
        creds["token"] = os.environ["GOVERNED_AUTONOMY_OPERATOR_TOKEN"]
    return creds


def save_credentials(api_url: str, token: str) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"api_url": api_url, "token": token}, handle)
    return path


def save_entra_credentials(
    api_url: str,
    tenant_id: str,
    client_id: str,
    scopes: Sequence[str],
) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "api_url": api_url,
                "tenant_id": tenant_id,
                "client_id": client_id,
                "scopes": list(scopes),
            },
            handle,
        )
    return path


class CLIError(Exception):
    pass


def _request(method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    creds = load_credentials()
    api_url = str(creds["api_url"]).rstrip("/")
    if urlsplit(api_url).scheme not in {"http", "https"}:
        raise CLIError("api_url must be http(s)")
    headers = {"Accept": "application/json"}
    token = creds.get("token")
    if creds.get("tenant_id") and creds.get("client_id"):
        config = EntraOIDCConfig(str(creds["tenant_id"]), str(creds["client_id"]))
        scopes = creds.get("scopes") or [f"api://{config.client_id}/access_as_user"]
        result = EntraDeviceAuthorizationClient(
            config,
            scopes=scopes,
            cache_path=config_path().with_name("entra.cache.bin"),
        ).acquire_token(output=lambda message: print(message, file=sys.stderr))
        token = result.get("access_token")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    request = Request(api_url + path, data=data, headers=headers, method=method)
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310  # nosec B310
            return json.loads(response.read() or b"null")
    except HTTPError as exc:
        raise CLIError(f"HTTP {exc.code} from {path}") from exc
    except URLError as exc:
        raise CLIError(f"cannot reach {api_url}: {exc.reason}") from exc


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="gas", description="Governed Autonomy Substrate CLI")
    sub = parser.add_subparsers(dest="group", required=True)

    auth = sub.add_parser("auth").add_subparsers(dest="cmd", required=True)
    login = auth.add_parser("login", help="sign in with Entra device authorization")
    login.add_argument("--api-url", default=DEFAULT_API_URL)
    login.add_argument("--tenant-id", default=os.environ.get("ENTRA_TENANT_ID"))
    login.add_argument("--client-id", default=os.environ.get("ENTRA_CLIENT_ID"))
    login.add_argument(
        "--scopes",
        nargs="+",
        default=None,
        help="API delegated scopes (default: api://<client-id>/access_as_user)",
    )
    login.add_argument(
        "--token",
        default=None,
        help="explicit bootstrap token override; otherwise use Entra device authorization",
    )
    auth.add_parser("status", help="check connectivity and credentials")

    keys = sub.add_parser("operator-key").add_subparsers(dest="cmd", required=True)
    keys.add_parser("list")
    create = keys.add_parser("create")
    create.add_argument("operator_id")
    revoke = keys.add_parser("revoke")
    revoke.add_argument("key_id")

    for name in ("policies", "proposals", "trust", "metrics", "audit", "governance-log"):
        sub.add_parser(name)

    policy = sub.add_parser("policy").add_subparsers(dest="cmd", required=True)
    show = policy.add_parser("show", help="show one active policy")
    show.add_argument("policy_id")

    registry = sub.add_parser("policy-registry").add_subparsers(dest="cmd", required=True)
    registry_list = registry.add_parser(
        "list", help="list immutable policy versions and lifecycle state"
    )
    registry_list.add_argument("policy_id")
    registry_inspect = registry.add_parser("inspect", help="inspect an immutable policy version")
    registry_inspect.add_argument("policy_id")
    registry_inspect.add_argument("version")
    registry_verify = registry.add_parser("verify", help="verify policy content and signature")
    registry_verify.add_argument("policy_id")
    registry_verify.add_argument("version")
    registry_active = registry.add_parser("active", help="show the active immutable policy version")
    registry_active.add_argument("policy_id")
    registry_history = registry.add_parser("history", help="show activation and rollback history")
    registry_history.add_argument("policy_id")
    registry_publish = registry.add_parser("publish", help="publish a signed policy JSON document")
    registry_publish.add_argument("policy", help="path to a policy JSON file")
    for command_name, help_text in (
        ("activate", "activate a verified policy version"),
        ("rollback", "roll back to a previously published policy version"),
        ("deprecate", "deprecate a non-active policy version"),
        ("revoke", "revoke a policy version"),
    ):
        command = registry.add_parser(command_name, help=help_text)
        command.add_argument("policy_id")
        command.add_argument("version")
        if command_name in {"activate", "rollback"}:
            command.add_argument("--reason", required=True)
            command.add_argument("--expected-revision", type=int, default=None)

    job = sub.add_parser("job").add_subparsers(dest="cmd", required=True)
    submit = job.add_parser("submit", help="enqueue a signed GAA for the worker")
    submit.add_argument("artifact", help="path to a GAA JSON file, or - for stdin")
    submit.add_argument("--idempotency-key", default=None, help="defaults to the artifact digest")
    submit.add_argument("--max-attempts", type=int, default=3)
    job_status = job.add_parser("status", help="show a queued job's status")
    job_status.add_argument("job_id")

    replay = sub.add_parser("replay").add_subparsers(dest="cmd", required=True)
    verify = replay.add_parser("verify", help="verify a local replay JSONL hash chain")
    verify.add_argument("path")
    return parser


_GET_ROUTES = {
    "policies": "/admin/policies",
    "proposals": "/admin/proposals",
    "trust": "/admin/trust",
    "metrics": "/admin/metrics",
    "audit": "/audit",
    "governance-log": "/admin/governance-log",
}


def run(args: argparse.Namespace) -> int:
    if args.group == "auth" and args.cmd == "login":
        token = args.token or os.environ.get("GOVERNED_AUTONOMY_OPERATOR_TOKEN")
        if not token:
            if not args.tenant_id or not args.client_id:
                raise CLIError(
                    "Entra device login requires --tenant-id and --client-id "
                    "(or ENTRA_TENANT_ID and ENTRA_CLIENT_ID)"
                )
            try:
                config = EntraOIDCConfig(args.tenant_id, args.client_id)
                scopes = args.scopes or [f"api://{config.client_id}/access_as_user"]
                scopes = tuple(scopes)
                EntraDeviceAuthorizationClient(
                    config,
                    scopes=scopes,
                    cache_path=config_path().with_name("entra.cache.bin"),
                ).acquire_token()
            except (RuntimeError, ValueError) as exc:
                raise CLIError(str(exc)) from exc
            path = save_entra_credentials(args.api_url, config.tenant_id, config.client_id, scopes)
        else:
            path = save_credentials(args.api_url, token)
        print(f"Saved credentials to {path}")
    elif args.group == "auth":
        _request("GET", "/admin/policies")
        print("Authenticated: operator credentials accepted.")
    elif args.group == "operator-key":
        if args.cmd == "list":
            _print(_request("GET", "/admin/operator-keys"))
        elif args.cmd == "create":
            _print(_request("POST", "/admin/operator-keys", {"operator_id": args.operator_id}))
            print("Store the token now; it cannot be shown again.", file=sys.stderr)
        else:
            revoke_path = f"/admin/operator-keys/{quote(args.key_id, safe='')}/revoke"
            _print(_request("POST", revoke_path, {}))
    elif args.group == "policy":
        payload = _request("GET", "/admin/policies").get("policies", {})
        items = payload.get("policies", []) if isinstance(payload, dict) else []
        found = next(
            (
                item
                for item in items
                if isinstance(item, dict)
                and args.policy_id
                in (item.get("policy_id"), item.get("policy", {}).get("policy_id"))
            ),
            None,
        )
        if found is None:
            raise CLIError(f"policy not found: {args.policy_id}")
        _print(found)
    elif args.group == "policy-registry":
        encoded_id = quote(args.policy_id, safe="") if hasattr(args, "policy_id") else ""
        if args.cmd == "list":
            _print(_request("GET", f"/admin/policy-registry/{encoded_id}"))
        elif args.cmd == "inspect":
            _print(
                _request(
                    "GET", f"/admin/policy-registry/{encoded_id}/{quote(args.version, safe='')}"
                )
            )
        elif args.cmd == "verify":
            result = _request(
                "GET",
                f"/admin/policy-registry/{encoded_id}/{quote(args.version, safe='')}/verify",
            )
            _print(result)
            return 0 if result.get("valid") else 1
        elif args.cmd == "active":
            _print(_request("GET", f"/admin/policy-registry/{encoded_id}/active"))
        elif args.cmd == "history":
            _print(_request("GET", f"/admin/policy-registry/{encoded_id}/history"))
        elif args.cmd == "publish":
            try:
                policy_payload = json.loads(Path(args.policy).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise CLIError("policy must be a readable JSON document") from exc
            if not isinstance(policy_payload, dict):
                raise CLIError("policy must be a JSON object")
            _print(_request("POST", "/admin/policy-registry/publish", {"policy": policy_payload}))
        else:
            body: dict[str, Any] = {"policy_id": args.policy_id, "version": args.version}
            if args.cmd in {"activate", "rollback"}:
                body["reason"] = args.reason
                if args.expected_revision is not None:
                    body["expected_revision"] = args.expected_revision
            _print(_request("POST", f"/admin/policy-registry/{args.cmd}", body))
    elif args.group == "job":
        if args.cmd == "submit":
            raw = (
                sys.stdin.read() if args.artifact == "-" else Path(args.artifact).read_text("utf-8")
            )
            artifact = json.loads(raw)
            if not isinstance(artifact, dict):
                raise CLIError("artifact must be a JSON object")
            key = (
                args.idempotency_key
                or hashlib.sha256(
                    json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
            )
            body = {"artifact": artifact, "idempotency_key": key, "max_attempts": args.max_attempts}
            _print(_request("POST", "/admin/jobs", body))
        else:
            _print(_request("GET", f"/admin/jobs/{quote(args.job_id, safe='')}"))
    elif args.group == "replay":
        report = ReplayLog.load_jsonl(args.path).verify_integrity()
        _print(report)
        return 0 if report["ok"] else 1
    else:
        _print(_request("GET", _GET_ROUTES[args.group]))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args)
    except (CLIError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
