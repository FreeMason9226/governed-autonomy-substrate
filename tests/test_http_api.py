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
    service, issuer, _ = build_demo_service()
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
    assert audit["actions"] == ["run_job", "write_file"]
    assert audit["audit_summary"]["execution_count"] == 1


def test_http_api_routes_query_bearing_urls_and_exposes_openapi_document(server):
    status, health = request(server, "GET", "/health?verbose=true")
    assert status == 200
    assert health["ok"] is True

    status, schema = request(server, "GET", "/openapi.json?format=json")
    assert status == 200
    assert schema["openapi"] == "3.0.3"
    assert "/api/v1/authorize" in schema["paths"]
    assert "/admin/operator-keys" in schema["paths"]
    assert "/admin/operator-keys/{key_id}/revoke" in schema["paths"]
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
    args = parse_server_args(
        [
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
            "--bearer-token",
            "super-secret",
            "--operator-key-store",
            "var/operator-keys.sqlite",
        ]
    )

    assert args.host == "0.0.0.0"
    assert args.port == 9000
    assert args.bearer_token == "super-secret"
    assert args.operator_key_store == "var/operator-keys.sqlite"


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


def test_http_api_admin_proposal_supports_mesh_governance_policy_fields():
    instance, thread, proposer, reviewer = _admin_server()
    try:
        policy = {
            "policy_id": "mesh-admin-v1",
            "allowed_actions": ["deploy"],
            "required_fields": {"deploy": ["target"]},
            "exact_fields": {"deploy": {}},
            "required_context": [],
            "exact_context": {},
            "max_request_bytes": 1024,
            "max_ttl_seconds": 60,
            "required_mesh_inputs": {"deploy": 2},
            "required_mesh_sources": {"deploy": ["sensor-a", "sensor-b"]},
            "mesh_required_actions": ["deploy"],
            "mesh_required_environments": ["prod"],
        }
        status, prepared = _admin_request(
            instance,
            "POST",
            "/admin/proposals/prepare",
            {"policy": policy, "proposer_key_id": proposer.key_id},
        )
        assert status == 200
        signature = proposer.sign(prepared["unsigned_payload"].encode("utf-8"))
        status, proposal = _admin_request(
            instance,
            "POST",
            "/admin/proposals",
            {
                "policy": policy,
                "proposal_id": prepared["proposal_id"],
                "proposer_key_id": proposer.key_id,
                "signature": signature,
            },
        )
        assert status == 201
        assert proposal["status"] == "pending"

        status, prepared_approval = _admin_request(
            instance,
            "POST",
            f"/admin/proposals/{prepared['proposal_id']}/prepare-approval",
            {"approver_key_id": reviewer.key_id},
        )
        assert status == 200
        approval_signature = reviewer.sign(prepared_approval["unsigned_payload"].encode("utf-8"))
        status, _approved = _admin_request(
            instance,
            "POST",
            f"/admin/proposals/{prepared['proposal_id']}/approve",
            {"approver_key_id": reviewer.key_id, "signature": approval_signature},
        )
        assert status == 200

        activated = _admin_request(
            instance, "POST", f"/admin/proposals/{prepared['proposal_id']}/activate"
        )
        assert activated[0] == 200
        assert activated[1]["policy_id"] == "mesh-admin-v1"
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


def test_http_api_admin_trust_add_and_revoke_key_round_trip():
    instance, thread, proposer, _reviewer = _admin_server()
    try:
        new_key = KeyPair.generate("new-trusted-key")
        from governed_autonomy.canonical import b64encode

        new_public_key_b64 = b64encode(new_key.public_key_bytes())

        status, prepared = _admin_request(
            instance,
            "POST",
            "/admin/trust/keys/prepare",
            {
                "key_id": new_key.key_id,
                "public_key_b64": new_public_key_b64,
                "requested_by_key_id": proposer.key_id,
            },
        )
        assert status == 200
        signature = proposer.sign(prepared["unsigned_payload"].encode("utf-8"))

        status, snapshot = _admin_request(
            instance,
            "POST",
            "/admin/trust/keys",
            {
                "key_id": new_key.key_id,
                "public_key_b64": new_public_key_b64,
                "requested_by_key_id": proposer.key_id,
                "signature": signature,
            },
        )
        assert status == 201
        assert new_key.key_id in snapshot["keys"]

        status, listing = _admin_request(instance, "GET", "/admin/trust")
        assert status == 200
        assert new_key.key_id in listing["keys"]

        status, prepared_revoke = _admin_request(
            instance,
            "POST",
            f"/admin/trust/keys/{new_key.key_id}/revoke/prepare",
            {"requested_by_key_id": proposer.key_id},
        )
        assert status == 200
        revoke_signature = proposer.sign(prepared_revoke["unsigned_payload"].encode("utf-8"))

        status, revoked_snapshot = _admin_request(
            instance,
            "POST",
            f"/admin/trust/keys/{new_key.key_id}/revoke",
            {"requested_by_key_id": proposer.key_id, "signature": revoke_signature},
        )
        assert status == 200
        assert new_key.key_id in revoked_snapshot["revoked"]

        status, governance_log = _admin_request(instance, "GET", "/admin/governance-log")
        assert status == 200
        events = [event["event"] for event in governance_log["events"]]
        subjects = [event["subject_id"] for event in governance_log["events"]]
        assert events == ["trust.key_added", "trust.key_revoked"]
        assert subjects == [new_key.key_id, new_key.key_id]
        assert all(event["recorded_at"] for event in governance_log["events"])
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_admin_trust_add_rejects_untrusted_requester():
    instance, thread, _proposer, _reviewer = _admin_server()
    try:
        outsider = KeyPair.generate("outsider")
        new_key = KeyPair.generate("new-trusted-key-2")
        from governed_autonomy.canonical import b64encode

        new_public_key_b64 = b64encode(new_key.public_key_bytes())

        status, prepared = _admin_request(
            instance,
            "POST",
            "/admin/trust/keys/prepare",
            {
                "key_id": new_key.key_id,
                "public_key_b64": new_public_key_b64,
                "requested_by_key_id": outsider.key_id,
            },
        )
        assert status == 200
        signature = outsider.sign(prepared["unsigned_payload"].encode("utf-8"))

        status, result = _admin_request(
            instance,
            "POST",
            "/admin/trust/keys",
            {
                "key_id": new_key.key_id,
                "public_key_b64": new_public_key_b64,
                "requested_by_key_id": outsider.key_id,
                "signature": signature,
            },
        )
        assert status == 400
        assert "signature" in result["error"]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_operator_keys_are_revocable_and_governance_events_attribute_actors(tmp_path):
    import sqlite3

    from governed_autonomy.operator_auth import OperatorKeyStore

    service, issuer, _ = build_demo_service()
    operator_store = OperatorKeyStore(tmp_path / "operator-keys.sqlite")
    instance = create_server(
        service,
        bearer_token="test-token",
        operator_token="bootstrap-operator-token",
        operator_key_store=operator_store,
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()

    def operator_request(method, path, payload=None, token="bootstrap-operator-token"):
        connection = HTTPConnection(*instance.server_address)
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Authorization": f"Bearer {token}"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    try:
        status, first = operator_request(
            "POST", "/admin/operator-keys", {"operator_id": "alice"}
        )
        assert status == 201
        assert first["token"].startswith("gasop_")
        with sqlite3.connect(tmp_path / "operator-keys.sqlite") as connection:
            token_hash = connection.execute(
                "SELECT token_hash FROM operator_api_keys WHERE key_id = ?",
                (first["key_id"],),
            ).fetchone()[0]
        assert first["token"] not in token_hash

        status, second = operator_request(
            "POST",
            "/admin/operator-keys",
            {"operator_id": "bob"},
            token=first["token"],
        )
        assert status == 201

        from governed_autonomy.canonical import b64encode

        delegated_key = KeyPair.generate("delegated-trusted-key")
        public_key_b64 = b64encode(delegated_key.public_key_bytes())
        status, prepared = operator_request(
            "POST",
            "/admin/trust/keys/prepare",
            {
                "key_id": delegated_key.key_id,
                "public_key_b64": public_key_b64,
                "requested_by_key_id": issuer.key_id,
            },
            token=second["token"],
        )
        assert status == 200
        trust_signature = issuer.sign(prepared["unsigned_payload"].encode("utf-8"))
        status, _ = operator_request(
            "POST",
            "/admin/trust/keys",
            {
                "key_id": delegated_key.key_id,
                "public_key_b64": public_key_b64,
                "requested_by_key_id": issuer.key_id,
                "signature": trust_signature,
            },
            token=second["token"],
        )
        assert status == 201

        status, key_list = operator_request(
            "GET", "/admin/operator-keys", token=second["token"]
        )
        assert status == 200
        assert {key["operator_id"] for key in key_list["keys"]} == {"alice", "bob"}
        assert all("token" not in key and "token_hash" not in key for key in key_list["keys"])

        status, _ = operator_request("GET", "/health", token=second["token"])
        assert status == 401

        status, revoked = operator_request(
            "POST",
            f"/admin/operator-keys/{first['key_id']}/revoke",
            token=second["token"],
        )
        assert status == 200
        assert revoked["revoked"] is True

        status, _ = operator_request("GET", "/admin/operator-keys", token=first["token"])
        assert status == 401

        status, audit = operator_request(
            "GET", "/admin/governance-log", token=second["token"]
        )
        assert status == 200
        events = audit["events"]
        assert [event["event"] for event in events] == [
            "operator.key_added",
            "operator.key_added",
            "trust.key_added",
            "operator.key_revoked",
        ]
        assert events[0]["actor_id"] == "shared-token"
        assert events[1]["actor_id"] == f"api-key:alice:{first['key_id']}"
        assert events[2]["actor_id"] == f"api-key:bob:{second['key_id']}"
        assert events[3]["actor_id"] == f"api-key:bob:{second['key_id']}"
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)
        operator_store.close()


def test_http_api_oidc_subject_is_recorded_as_governance_actor():
    from governed_autonomy import ExternalIdentity

    class StubOIDCValidator:
        def validate(self, token):
            assert token == "signed-oidc-token"
            return ExternalIdentity(
                subject="operator-42",
                issuer="https://identity.example",
                claims={"roles": ["gas-admin"]},
            )

    service, issuer, _ = build_demo_service()
    instance = create_server(
        service,
        bearer_token="unused",
        oidc_validator=StubOIDCValidator(),
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()

    def oidc_request(method, path, payload=None):
        connection = HTTPConnection(*instance.server_address)
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Authorization": "Bearer signed-oidc-token"}
        if body is not None:
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(body))
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        return response.status, result

    try:
        policy = {
            "policy_id": "oidc-attributed-policy",
            "allowed_actions": ["write_file"],
            "required_fields": {"write_file": ["path", "content"]},
            "exact_fields": {"write_file": {"path": "oidc.txt"}},
            "required_context": [],
            "exact_context": {},
            "max_request_bytes": 1024,
            "max_ttl_seconds": 60,
        }
        status, prepared = oidc_request(
            "POST",
            "/admin/proposals/prepare",
            {
                "policy": policy,
                "proposer_key_id": issuer.key_id,
                "rationale": "test operator identity attribution",
            },
        )
        assert status == 200
        signature = issuer.sign(prepared["unsigned_payload"].encode("utf-8"))

        status, _ = oidc_request(
            "POST",
            "/admin/proposals",
            {
                "policy": policy,
                "proposer_key_id": issuer.key_id,
                "rationale": "test operator identity attribution",
                "signature": signature,
            },
        )
        assert status == 201

        status, audit = oidc_request("GET", "/admin/governance-log")
        assert status == 200
        assert audit["events"][0]["actor_id"] == (
            "oidc:https://identity.example:operator-42"
        )
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_admin_trust_revoke_unknown_key_returns_404():
    instance, thread, proposer, _reviewer = _admin_server()
    try:
        status, prepared = _admin_request(
            instance,
            "POST",
            "/admin/trust/keys/does-not-exist/revoke/prepare",
            {"requested_by_key_id": proposer.key_id},
        )
        assert status == 200
        signature = proposer.sign(prepared["unsigned_payload"].encode("utf-8"))
        status, result = _admin_request(
            instance,
            "POST",
            "/admin/trust/keys/does-not-exist/revoke",
            {"requested_by_key_id": proposer.key_id, "signature": signature},
        )
        assert status == 404
        assert "does-not-exist" in result["error"]
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)

def test_admin_jobs_endpoint_enqueues_and_is_idempotent():
    from governed_autonomy import SQLiteJobStore

    service, _, _ = build_demo_service()
    store = SQLiteJobStore()
    instance = create_server(service, bearer_token="test-token", job_store=store)
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        body = {"artifact": {"x": 1}, "idempotency_key": "k1"}
        status, first = request(instance, "POST", "/admin/jobs", body)
        assert status == 403  # operator authorization required
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)

    instance = create_server(
        service, bearer_token="test-token", operator_token="test-token", job_store=store
    )
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        status, first = request(instance, "POST", "/admin/jobs", body)
        assert status == 202 and first["status"] == "queued"
        status, again = request(instance, "POST", "/admin/jobs", body)
        assert again["job_id"] == first["job_id"]
        serialized_body = {
            **body,
            "artifact": json.dumps(body["artifact"], separators=(",", ":")),
        }
        status, serialized_again = request(instance, "POST", "/admin/jobs", serialized_body)
        assert status == 202 and serialized_again["job_id"] == first["job_id"]
        status, state = request(instance, "GET", f"/admin/jobs/{first['job_id']}")
        assert status == 200 and state["status"] == "queued"
        assert state["attempts"] == 0 and "payload" not in state
        status, _ = request(instance, "POST", "/admin/jobs", {"artifact": "no", "idempotency_key": "k"})
        assert status == 400
        claimed = store.claim()
        assert claimed is not None
        assert json.loads(claimed.payload["artifact"]) == {"x": 1}
        store.complete(claimed.job_id)
        status, state = request(instance, "GET", f"/admin/jobs/{first['job_id']}")
        assert status == 200 and state["status"] == "succeeded"
        status, _ = request(instance, "GET", "/admin/jobs/unknown")
        assert status == 404
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_admin_jobs_endpoint_unconfigured_returns_503():
    service, _, _ = build_demo_service()
    instance = create_server(service, bearer_token="test-token", operator_token="test-token")
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()
    try:
        status, _ = request(instance, "POST", "/admin/jobs", {})
        assert status == 503
        status, _ = request(instance, "GET", "/admin/jobs/unknown")
        assert status == 503
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_http_api_cors_is_opt_in_and_origin_scoped():
    service, _, _ = build_demo_service()
    allowed = "https://demo.example.com"
    plain = create_server(service, bearer_token="test-token")
    cors = create_server(service, bearer_token="test-token", cors_origins=[allowed + "/"])
    servers = [plain, cors]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()

    def call(s, method, origin, headers=None):
        connection = HTTPConnection(*s.server_address)
        connection.request(method, "/livez", headers={"Origin": origin, **(headers or {})})
        response = connection.getresponse()
        response.read()
        result = (response.status, response.getheader("Access-Control-Allow-Origin"), response)
        connection.close()
        return result

    try:
        assert call(plain, "OPTIONS", allowed)[:2] == (403, None)
        status, origin, response = call(cors, "OPTIONS", allowed)
        assert (status, origin) == (204, allowed)
        assert "Authorization" in response.getheader("Access-Control-Allow-Headers")
        assert call(cors, "OPTIONS", "https://evil.example.com")[:2] == (403, None)
        status, origin, response = call(
            cors, "GET", allowed, {"Authorization": "Bearer test-token"}
        )
        assert (status, origin) == (200, allowed)
        assert response.getheader("Vary") == "Origin"
        assert call(cors, "GET", "https://evil.example.com", {"Authorization": "Bearer test-token"})[1] is None
        assert call(plain, "GET", allowed, {"Authorization": "Bearer test-token"})[1] is None
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()

def test_http_api_auditor_role_is_read_only():
    from governed_autonomy import ExternalIdentity

    class StubOIDCValidator:
        def validate(self, token):
            return ExternalIdentity(
                subject="aud-1", issuer="https://identity.example", claims={"roles": ["auditor"]}
            )

    service, _, _ = build_demo_service()
    instance = create_server(service, bearer_token="unused", oidc_validator=StubOIDCValidator())
    thread = threading.Thread(target=instance.serve_forever, daemon=True)
    thread.start()

    def call(method, path, payload=b""):
        connection = HTTPConnection(*instance.server_address)
        headers = {"Authorization": "Bearer t", "Content-Length": str(len(payload))}
        connection.request(method, path, body=payload or None, headers=headers)
        status = connection.getresponse().status
        connection.close()
        return status

    try:
        assert call("GET", "/admin/policies") == 200
        assert call("POST", "/admin/proposals/prepare", b"{}") == 403
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def test_json_log_formatter_emits_extras():
    import json as _json
    import logging as _logging

    from governed_autonomy.logging_config import JsonFormatter

    record = _logging.LogRecord("governed_autonomy.access", _logging.INFO, "", 0, "request", None, None)
    record.status = "200"
    out = _json.loads(JsonFormatter().format(record))
    assert out["message"] == "request" and out["status"] == "200" and out["level"] == "INFO"


def test_openapi_documents_responses():
    from governed_autonomy.http_api import API_SCHEMA

    post = API_SCHEMA["paths"]["/api/v1/authorize"]["post"]["responses"]
    assert "400" in post and "content" in post["200"]
    assert "ExecuteResponse" in API_SCHEMA["components"]["schemas"]


def test_versioned_read_routes_map_to_canonical():
    from governed_autonomy.http_api import _unversioned

    assert _unversioned("/api/v1/readyz") == "/readyz"
    assert _unversioned("/api/v1/admin/jobs") == "/api/v1/admin/jobs"
    assert _unversioned("/readyz") == "/readyz"


def test_openapi_admin_operations_have_schemas():
    from governed_autonomy.http_api import API_SCHEMA

    assert "/api/v1/readyz" in API_SCHEMA["paths"]
    resp = API_SCHEMA["paths"]["/admin/policies"]["get"]["responses"]
    assert "content" in resp["200"] and "401" in resp and "403" in resp
