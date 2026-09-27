
import time

from fastapi.testclient import TestClient

from governed_autonomy import InMemoryControlPlaneRepository, create_app
from governed_autonomy.bootstrap import build_platform_demo


class _AppHarness:
    def __init__(self):
        platform, service, _, _ = build_platform_demo(actor_id="tester", tenant_id="tenant-a")
        control_plane = InMemoryControlPlaneRepository()
        for policy in service.policies.policies():
            control_plane.save_policy(policy, published=True)
        self.platform = platform
        self.control_plane = control_plane
        self.app = create_app(
            platform=platform,
            control_plane=control_plane,
            bearer_token="test-token",
        )
        self.client = TestClient(self.app)
        self.headers = {"Authorization": "Bearer " + "test-token", "X-Request-ID": "req-123"}


def test_fastapi_authorize_execute_audit_and_openapi_flow():
    harness = _AppHarness()
    response = harness.client.post(
        "/v1/authorize",
        headers={**harness.headers, "Idempotency-Key": "auth-1"},
        json={
            "policy_id": "demo-files-v1",
            "request": {"action": "write_file", "path": "out.txt", "content": "api"},
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "authorized"
    authorization_id = payload["authorization_id"]
    artifact = payload["artifact"]
    assert artifact["decision"]["allow"] is True
    assert response.headers["X-Request-ID"] == "req-123"

    repeat = harness.client.post(
        "/v1/authorize",
        headers={**harness.headers, "Idempotency-Key": "auth-1"},
        json={
            "policy_id": "demo-files-v1",
            "request": {"action": "write_file", "path": "out.txt", "content": "api"},
        },
    )
    assert repeat.status_code == 200
    assert repeat.json()["authorization_id"] == authorization_id

    execute = harness.client.post(
        "/v1/execute",
        headers=harness.headers,
        json={"authorization_id": authorization_id},
    )
    assert execute.status_code == 200
    assert execute.json()["status"] == "executed"
    assert execute.json()["result"] == "api"

    fetched = harness.client.get(f"/v1/authorizations/{authorization_id}", headers=harness.headers)
    assert fetched.status_code == 200
    assert fetched.json()["artifact"] == artifact

    events = harness.client.get("/v1/audit/events", headers=harness.headers)
    assert events.status_code == 200
    assert any(event["type"] == "authorization" for event in events.json()["events"])

    reports = harness.client.get("/v1/audit/reports", headers=harness.headers)
    assert reports.status_code == 200
    assert reports.json()["verify_chain"] is True

    openapi = harness.client.get("/v1/openapi.json")
    assert openapi.status_code == 200
    assert "/v1/authorize" in openapi.json()["paths"]


def test_fastapi_policy_principal_and_approval_flows():
    harness = _AppHarness()
    create_policy = harness.client.post(
        "/v1/policies",
        headers=harness.headers,
        json={
            "policy": {
                "policy_id": "approval-policy",
                "allowed_actions": ["write_file"],
                "required_fields": {"write_file": ["path", "content"]},
                "exact_fields": {},
                "required_context": [],
                "exact_context": {},
                "max_request_bytes": 65536,
                "max_ttl_seconds": 300,
                "required_approvals": {"write_file": 1},
            }
        },
    )
    assert create_policy.status_code == 201
    publish = harness.client.post(
        "/v1/policies/approval-policy/publish",
        headers=harness.headers,
        json={},
    )
    assert publish.status_code == 200
    assert publish.json()["published"] is True

    principal = harness.client.post(
        "/v1/principals",
        headers=harness.headers,
        json={"principal_id": "worker-a", "allowed_actions": ["write_file"]},
    )
    assert principal.status_code == 201
    assert principal.json()["principal_id"] == "worker-a"

    pending = harness.client.post(
        "/v1/authorize",
        headers=harness.headers,
        json={
            "policy_id": "approval-policy",
            "request": {"action": "write_file", "path": "out.txt", "content": "pending"},
            "ttl_seconds": 1,
        },
    )
    assert pending.status_code == 202
    pending_payload = pending.json()
    assert pending_payload["status"] == "awaiting_approval"

    approved = harness.client.post(
        f"/v1/authorizations/{pending_payload['authorization_id']}/approve",
        headers=harness.headers,
        json={"actor_id": "approver-1"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "authorized"
    assert approved.json()["approvals_count"] == 1
    assert approved.json()["artifact"]["expires_at"] <= int(time.time()) + 1

    revoked = harness.client.post(
        "/v1/principals/worker-a/revoke",
        headers=harness.headers,
        json={},
    )
    assert revoked.status_code == 200
    assert revoked.json()["key_status"] == "revoked"


def test_fastapi_problem_detail_errors_include_request_id():
    harness = _AppHarness()

    unauthorized = harness.client.get("/v1/health")
    assert unauthorized.status_code == 401
    assert unauthorized.json()["title"] == "request failed"

    bad_request = harness.client.put(
        "/v1/policies/demo-files-v1",
        headers=harness.headers,
        json={
            "policy": {
                "policy_id": "different-id",
                "allowed_actions": ["write_file"],
                "required_fields": {"write_file": ["content", "path"]},
                "exact_fields": {},
                "required_context": [],
                "exact_context": {},
                "max_request_bytes": 65536,
                "max_ttl_seconds": 300,
                "required_approvals": {},
            }
        },
    )
    assert bad_request.status_code == 400
    assert bad_request.headers["X-Request-ID"] == "req-123"
    assert bad_request.json()["request_id"] == "req-123"

    forbidden = harness.client.post(
        "/v1/authorize",
        headers=harness.headers,
        json={
            "policy_id": "demo-files-v1",
            "request": {"action": "delete_file", "path": "out.txt"},
        },
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["status"] == 403

    missing = harness.client.get("/v1/authorizations/does-not-exist", headers=harness.headers)
    assert missing.status_code == 404
    assert missing.json()["request_id"] == "req-123"
