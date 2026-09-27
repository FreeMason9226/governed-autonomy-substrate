import importlib
import json
import sys
import types

from governed_autonomy.api.app import AppContext
from governed_autonomy.bootstrap import build_platform_demo
from governed_autonomy.cli import main
from governed_autonomy.control_plane import InMemoryControlPlaneRepository
from governed_autonomy.platform import ServicePrincipalRegistry


def test_cli_parser_flows(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GAS_RUNTIME_MODE", "memory")
    platform, service, _, _ = build_platform_demo()
    control_plane = InMemoryControlPlaneRepository()
    for policy in service.policies.policies():
        control_plane.save_policy(policy, published=True)
    context = AppContext(
        platform=platform,
        control_plane=control_plane,
        principal_registry=ServicePrincipalRegistry(),
    )
    cli_main = importlib.import_module("governed_autonomy.cli.main")
    monkeypatch.setattr(cli_main, "_build_default_context", lambda: context)

    assert main(["tenant", "create", "tenant-a", "--name", "Tenant A"]) == 0
    tenant_out = json.loads(capsys.readouterr().out)
    assert tenant_out["tenant_id"] == "tenant-a"

    principal_file = tmp_path / "principal.json"
    principal_file.write_text(json.dumps({"principal_id": "worker-a", "allowed_actions": ["write_file"]}), encoding="utf-8")
    assert main(["principal", "register", str(principal_file)]) == 0
    principal_out = json.loads(capsys.readouterr().out)
    assert principal_out["principal_id"] == "worker-a"
    assert main(["principal", "revoke", "worker-a"]) == 0
    revoke_out = json.loads(capsys.readouterr().out)
    assert revoke_out["status"] == "revoked"

    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "policy": {
                    "policy_id": "cli-policy",
                    "allowed_actions": ["write_file"],
                    "required_fields": {"write_file": ["content", "path"]},
                    "exact_fields": {},
                    "required_context": [],
                    "exact_context": {},
                    "max_request_bytes": 65536,
                    "max_ttl_seconds": 300,
                    "required_approvals": {},
                }
            }
        ),
        encoding="utf-8",
    )
    assert main(["policy", "publish", str(policy_file)]) == 0
    policy_out = json.loads(capsys.readouterr().out)
    assert policy_out["policy_id"] == "cli-policy"

    authorization = control_plane.create_authorization(
        policy_id="demo-files-v1",
        request_payload={"action": "write_file", "path": "out.txt", "content": "cli"},
        context={},
        mesh_inputs=[],
        request_digest="digest-cli",
        idempotency_key=None,
        ttl_seconds=300,
        required_approvals=0,
    )
    assert main(["authorization", "inspect", authorization.authorization_id]) == 0
    auth_out = json.loads(capsys.readouterr().out)
    assert auth_out["authorization_id"] == authorization.authorization_id

    class _FakeConnection:
        def close(self) -> None:
            return None

    fake_psycopg = types.SimpleNamespace(connect=lambda _: _FakeConnection())
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    monkeypatch.setattr(cli_main, "run_postgres_migrations", lambda connection: ["002_control_plane.sql"])
    assert main(["migrate", "--database-url", "******localhost:5432/gas"]) == 0
    migrate_out = json.loads(capsys.readouterr().out)
    assert migrate_out["applied"] == ["002_control_plane.sql"]
