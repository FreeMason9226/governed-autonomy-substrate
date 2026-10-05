import threading
from http.client import HTTPConnection

from governed_autonomy import build_demo_service, create_server
from governed_autonomy.identity import IdentityValidationError, OIDCDiscoveryDocument


class RejectingOIDCValidator:
    def validate(self, token: str):
        raise IdentityValidationError("invalid token")


def _get(server, path: str, token: str) -> int:
    connection = HTTPConnection(*server.server_address)
    connection.request("GET", path, headers={"Authorization": f"Bearer {token}"})
    response = connection.getresponse()
    response.read()
    connection.close()
    return response.status


def test_entra_only_auth_rejects_legacy_token_except_health_probe():
    service, _, _ = build_demo_service()
    server = create_server(
        service,
        bearer_token="probe-token",
        oidc_validator=RejectingOIDCValidator(),
        oidc_only=True,
        operator_token="legacy-operator",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert _get(server, "/audit", "probe-token") == 401
        assert _get(server, "/health", "probe-token") == 200
        assert _get(server, "/admin", "legacy-operator") == 401
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_server_cli_uses_tenant_bound_oidc_without_shared_api_token(monkeypatch):
    from governed_autonomy import http_api

    captured = {}
    validator = object()

    class StoppedServer:
        server_address = ("127.0.0.1", 8000)

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    monkeypatch.delenv("OIDC_ISSUER", raising=False)
    monkeypatch.delenv("OIDC_AUDIENCE", raising=False)
    monkeypatch.delenv("OIDC_JWKS_URL", raising=False)
    monkeypatch.delenv("OIDC_DISCOVERY", raising=False)
    monkeypatch.setattr(http_api, "configure_logging", lambda: None)
    monkeypatch.setattr(
        http_api,
        "discover_oidc_configuration",
        lambda issuer: OIDCDiscoveryDocument(
            issuer=issuer,
            jwks_uri="https://login.microsoftonline.com/tenant/keys",
        ),
    )
    monkeypatch.setattr(
        http_api,
        "entra_oidc_validator_from_discovery",
        lambda config, *, discovery: validator,
    )
    monkeypatch.setattr(
        http_api, "build_runtime_service", lambda: ("service", None, None)
    )

    def capture_server(service, **kwargs):
        captured.update(kwargs)
        return StoppedServer()

    monkeypatch.setattr(http_api, "create_server", capture_server)
    http_api.main(
        [
            "--entra-tenant-id",
            "11111111-1111-4111-8111-111111111111",
            "--entra-client-id",
            "22222222-2222-4222-8222-222222222222",
            "--bearer-token",
            "probe-token",
        ]
    )
    assert captured["oidc_validator"] is validator
    assert captured["oidc_only"] is True
    assert captured["bearer_token"] == "probe-token"
