import json
import threading
from http.client import HTTPConnection

import pytest

from governed_autonomy import build_demo_service, create_server, parse_server_args


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


def test_http_api_parse_server_args_supports_cli_options():
    args = parse_server_args(["--host", "0.0.0.0", "--port", "9000", "--bearer-token", "super-secret"])

    assert args.host == "0.0.0.0"
    assert args.port == 9000
    assert args.bearer_token == "super-secret"
