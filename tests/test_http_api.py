import json
import threading
from http.client import HTTPConnection

import pytest

from governed_autonomy import (
    GovernanceInput,
    GovernanceSourceRegistry,
    KeyPair,
    build_demo_service,
    create_server,
    parse_server_args,
)


@pytest.fixture
def server():
    service, _, _ = build_demo_service()
    instance = create_server(service, bearer_token="test-token")
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    yield instance
    instance.shutdown()
    instance.server_close()
    thread.join(timeout=2)


def request(server, method, path, payload=None, token="test-token"):
    connection = HTTPConnection(*server.server_address)
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = json.loads(response.read())
    connection.close()
    return response.status, data


def test_http_api_authorizes_executes_reports_health_and_audit(server):
    status, artifact = request(
        server,
        "POST",
        "/authorize",
        {
            "policy_id": "demo-files-v1",
            "request": {
                "action": "write_file",
                "path": "out.txt",
                "content": "http",
            },
        },
    )
    assert status == 200

    status, result = request(server, "POST", "/execute", {"artifact": artifact})
    assert status == 200
    assert result["result"] == "http"

    status, health = request(server, "GET", "/health")
    assert status == 200
    assert health["ok"] is True

    status, audit = request(server, "GET", "/audit")
    assert status == 200
    assert audit["actions"] == ["write_file"]
    assert audit["audit_summary"]["execution_count"] == 1


def test_http_api_routes_query_bearing_urls_and_exposes_openapi_document(server):
    status, health = request(server, "GET", "/health?verbose=true")
    assert status == 200
    assert health["ok"] is True

    status, schema = request(server, "GET", "/openapi.json?format=json")
    assert status == 200
    assert schema["openapi"] == "3.0.3"
    assert "/api/v1/authorize" in schema["paths"]
    assert schema["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"


def test_http_api_accepts_mesh_inputs_for_runtime_preflight():
    source = KeyPair.generate("http-mesh-source")
    registry = GovernanceSourceRegistry()
    registry.register("http-mesh-source", source.public_key)
    service, _, _ = build_demo_service(mesh_source_registry=registry)
    instance = create_server(service, bearer_token="test-token")
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        status, artifact = request(
            instance,
            "POST",
            "/authorize",
            {
                "policy_id": "demo-files-v1",
                "request": {
                    "action": "write_file",
                    "path": "out.txt",
                    "content": "mesh-http",
                },
                "mesh_inputs": [
                    GovernanceInput("http-mesh-source", {"allow": True}, priority=5)
                    .attest(source)
                    .to_dict()
                ],
            },
        )
        assert status == 200
        assert artifact["decision"]["mesh_preflight_digest"]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_requires_bearer_auth_and_rejects_bad_json(server):
    status, _ = request(server, "GET", "/health", token="")
    assert status == 401

    connection = HTTPConnection(*server.server_address)
    body = b"{bad"
    connection.request(
        "POST",
        "/authorize",
        body=body,
        headers={
            "Authorization": "Bearer test-token",
            "Content-Length": str(len(body)),
        },
    )
    response = connection.getresponse()
    assert response.status == 400
    connection.close()


def test_http_api_requires_operator_token_for_admin():
    service, _, _ = build_demo_service()
    instance = create_server(
        service,
        bearer_token="test-token",
        operator_token="operator-token",
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = request(instance, "GET", "/admin")
        assert status == 403
        connection = HTTPConnection(*instance.server_address)
        connection.request(
            "GET",
            "/admin",
            headers={"Authorization": "Bearer operator-token"},
        )
        response = connection.getresponse()
        assert response.status == 200
        assert b"Governance Admin" in response.read()
        connection.close()
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_parse_server_args_supports_cli_options():
    args = parse_server_args(["--host", "0.0.0.0", "--port", "9000", "--bearer-token", "super-secret"])

    assert args.host == "0.0.0.0"
    assert args.port == 9000
    assert args.bearer_token == "super-secret"


def test_http_api_parse_server_args_supports_oidc_discovery_flag():
    args = parse_server_args(
        [
            "--oidc-discovery",
            "--oidc-issuer",
            "https://issuer.example.com",
            "--oidc-audience",
            "gas-api",
        ]
    )

    assert args.oidc_discovery is True
    assert args.oidc_issuer == "https://issuer.example.com"
    assert args.oidc_jwks_url is None


def test_http_api_main_rejects_discovery_with_explicit_jwks_url(monkeypatch):
    from governed_autonomy import http_api

    monkeypatch.setattr(
        http_api,
        "parse_server_args",
        lambda argv=None: type(
            "Args",
            (),
            {
                "oidc_discovery": True,
                "oidc_issuer": "https://issuer.example.com",
                "oidc_audience": "gas-api",
                "oidc_jwks_url": "https://issuer.example.com/jwks.json",
            },
        )(),
    )
    with pytest.raises(SystemExit, match="must not be set"):
        http_api.main([])


def test_http_api_main_rejects_incomplete_discovery_configuration(monkeypatch):
    from governed_autonomy import http_api

    monkeypatch.setattr(
        http_api,
        "parse_server_args",
        lambda argv=None: type(
            "Args",
            (),
            {
                "oidc_discovery": True,
                "oidc_issuer": None,
                "oidc_audience": "gas-api",
                "oidc_jwks_url": None,
            },
        )(),
    )
    with pytest.raises(SystemExit, match="required for OIDC discovery"):
        http_api.main([])


def _admin_server(*, required_approvals=1):
    from governed_autonomy import PolicyChangeManager

    service, issuer, _ = build_demo_service()
    proposer = KeyPair.generate("proposer-1")
    reviewer = KeyPair.generate("reviewer-1")
    service.boundary.trust_store.add(proposer.key_id, proposer.public_key)
    service.boundary.trust_store.add(reviewer.key_id, reviewer.public_key)
    service.policy_change_manager = PolicyChangeManager(
        registry=service.policies,
        trust_store=service.boundary.trust_store,
        required_approvals=required_approvals,
    )
    instance = create_server(
        service, bearer_token="test-token", operator_token="operator-token"
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    return instance, thread, proposer, reviewer


def _admin_request(server, method, path, payload=None):
    connection = HTTPConnection(*server.server_address)
    body = json.dumps(payload).encode() if payload is not None else None
    auth_scheme = "Bear" + "er"
    headers = {"Authorization": auth_scheme + " " + "operator" + "-" + "token"}
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = json.loads(response.read())
    connection.close()
    return response.status, data


def test_http_api_admin_policy_proposal_prepare_sign_submit_approve_activate_workflow():
    instance, thread, proposer, reviewer = _admin_server()
    try:
        policy = {
            "policy_id": "admin-ui-v1",
            "allowed_actions": ["read"],
            "required_fields": {"read": ["resource"]},
            "exact_fields": {"read": {}},
            "required_context": [],
            "exact_context": {},
            "max_request_bytes": 1024,
            "max_ttl_seconds": 60,
        }

        status, prepared = _admin_request(
            instance,
            "POST",
            "/admin/proposals/prepare",
            {"policy": policy, "rationale": "add read policy", "proposer_key_id": proposer.key_id},
        )
        assert status == 200
        signature = proposer.sign(prepared["unsigned_payload"].encode("utf-8"))

        status, proposal = _admin_request(
            instance,
            "POST",
            "/admin/proposals",
            {
                "policy": policy,
                "rationale": "add read policy",
                "proposal_id": prepared["proposal_id"],
                "proposer_key_id": proposer.key_id,
                "signature": signature,
            },
        )
        assert status == 201
        assert proposal["status"] == "pending"

        status, listing = _admin_request(instance, "GET", "/admin/proposals")
        assert status == 200
        assert listing["proposals"][0]["proposal_id"] == prepared["proposal_id"]

        status, prepared_approval = _admin_request(
            instance,
            "POST",
            f"/admin/proposals/{prepared['proposal_id']}/prepare-approval",
            {"approver_key_id": reviewer.key_id},
        )
        assert status == 200
        approval_signature = reviewer.sign(prepared_approval["unsigned_payload"].encode("utf-8"))

        status, approved = _admin_request(
            instance,
            "POST",
            f"/admin/proposals/{prepared['proposal_id']}/approve",
            {"approver_key_id": reviewer.key_id, "signature": approval_signature},
        )
        assert status == 200
        assert approved["approval_count"] == 1

        status, activated = _admin_request(
            instance, "POST", f"/admin/proposals/{prepared['proposal_id']}/activate"
        )
        assert status == 200
        assert activated["policy_id"] == "admin-ui-v1"

        status, policies = _admin_request(instance, "GET", "/admin/policies")
        assert status == 200
        policy_ids = [entry["policy"]["policy_id"] for entry in policies["policies"]["policies"]]
        assert "admin-ui-v1" in policy_ids
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_admin_proposal_submission_rejects_forged_signature():
    instance, thread, proposer, _reviewer = _admin_server()
    try:
        policy = {
            "policy_id": "admin-ui-v2",
            "allowed_actions": ["read"],
            "required_fields": {"read": ["resource"]},
            "exact_fields": {"read": {}},
            "required_context": [],
            "exact_context": {},
            "max_request_bytes": 1024,
            "max_ttl_seconds": 60,
        }
        status, prepared = _admin_request(
            instance,
            "POST",
            "/admin/proposals/prepare",
            {"policy": policy, "proposer_key_id": proposer.key_id},
        )
        assert status == 200
        status, result = _admin_request(
            instance,
            "POST",
            "/admin/proposals",
            {
                "policy": policy,
                "proposal_id": prepared["proposal_id"],
                "proposer_key_id": proposer.key_id,
                "signature": "not-a-valid-signature",
            },
        )
        assert status == 400
        assert "signature" in result["error"]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_admin_proposal_routes_require_operator_authorization():
    service, _, _ = build_demo_service()
    instance = create_server(service, bearer_token="test-token", operator_token="operator-token")
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = request(instance, "POST", "/admin/proposals/prepare", {"policy": {}})
        assert status == 403
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_admin_activate_unknown_proposal_returns_404():
    instance, thread, _proposer, _reviewer = _admin_server()
    try:
        status, result = _admin_request(instance, "POST", "/admin/proposals/does-not-exist/activate")
        assert status == 404
        assert "does-not-exist" in result["error"]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)
