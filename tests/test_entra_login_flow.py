import base64
import hashlib
import json
import threading
import time
from http.client import HTTPConnection
from urllib.parse import parse_qs, urlsplit

from governed_autonomy import (
    ExternalIdentity,
    OIDCAuthCodeClient,
    OIDCDiscoveryDocument,
    build_demo_service,
    create_server,
)
from governed_autonomy.identity import IdentityValidationError


class StubOIDCValidator:
    expected_nonce = None

    def validate(self, token, *, nonce=None):
        if (
            token != "verified-id-token"
            or self.expected_nonce is None
            or nonce != self.expected_nonce
        ):
            raise IdentityValidationError("invalid token")
        return ExternalIdentity(
            subject="user-42",
            issuer="https://login.microsoftonline.com/tenant-id/v2.0",
            claims={
                "tid": "tenant-id",
                "name": "Entra User",
                "email": "user@example.com",
                "roles": ["operator"],
                "exp": time.time() + 3600,
            },
        )


def _request(server, method, path, *, headers=None, body=None):
    connection = HTTPConnection(*server.server_address)
    request_headers = dict(headers or {})
    if body is not None:
        encoded = json.dumps(body).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
        request_headers["Content-Length"] = str(len(encoded))
    else:
        encoded = None
    connection.request(method, path, body=encoded, headers=request_headers)
    response = connection.getresponse()
    content = response.read()
    response_headers = dict(response.getheaders())
    response_headers["Set-Cookie"] = response.headers.get_all("Set-Cookie") or []
    result = (response.status, response_headers, content)
    connection.close()
    return result


def test_entra_authorization_code_flow_creates_and_revokes_browser_session(monkeypatch):
    discovery = OIDCDiscoveryDocument(
        issuer="https://login.microsoftonline.com/tenant-id/v2.0",
        jwks_uri="https://login.microsoftonline.com/tenant-id/keys",
        authorization_endpoint="https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
        token_endpoint="https://login.microsoftonline.com/tenant-id/oauth2/v2.0/token",
    )
    auth_client = OIDCAuthCodeClient(
        discovery=discovery,
        client_id="client-id",
        client_secret="client-secret",
        redirect_uri="https://gas.example.com/auth/callback",
    )
    exchanged = {}

    def exchange_code(*, code, code_verifier):
        exchanged.update(code=code, code_verifier=code_verifier)
        return {"id_token": "verified-id-token"}

    monkeypatch.setattr(auth_client, "exchange_code", exchange_code)
    service, _, _ = build_demo_service()
    validator = StubOIDCValidator()
    server = create_server(
        service,
        oidc_validator=validator,
        oidc_login_validator=validator,
        oidc_auth_client=auth_client,
        oidc_only=True,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, _ = _request(server, "GET", "/auth/login?next=%2Fadmin")
        assert status == 302
        authorization_url = headers["Location"]
        authorization_query = parse_qs(urlsplit(authorization_url).query)
        assert authorization_query["client_id"] == ["client-id"]
        assert authorization_query["redirect_uri"] == [
            "https://gas.example.com/auth/callback"
        ]
        assert authorization_query["response_type"] == ["code"]
        assert authorization_query["scope"] == ["openid profile email"]
        assert authorization_query["code_challenge_method"] == ["S256"]
        state = authorization_query["state"][0]
        validator.expected_nonce = authorization_query["nonce"][0]
        state_cookie = headers["Set-Cookie"][0].split(";", 1)[0]
        callback_path = f"/auth/callback?code=authorization-code&state={state}"
        status, _, _ = _request(server, "GET", callback_path)
        assert status == 400
        status, callback_headers, _ = _request(
            server, "GET", callback_path, headers={"Cookie": state_cookie}
        )
        assert status == 302
        assert callback_headers["Location"] == "/admin"
        cookie = next(
            value
            for value in callback_headers["Set-Cookie"]
            if value.startswith("__Host-gas-session=")
        )
        assert any(
            value.startswith("__Host-gas-login=") and "Max-Age=0" in value
            for value in callback_headers["Set-Cookie"]
        )
        assert cookie.startswith("__Host-gas-session=")
        assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Lax" in cookie
        assert exchanged["code"] == "authorization-code"
        expected_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(exchanged["code_verifier"].encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert authorization_query["code_challenge"] == [expected_challenge]

        session_cookie = cookie.split(";", 1)[0]
        status, _, content = _request(
            server,
            "GET",
            "/admin",
            headers={"Cookie": session_cookie},
        )
        assert status == 200
        assert b"Governance Admin" in content

        status, _, _ = _request(
            server,
            "POST",
            "/authorize",
            headers={
                "Cookie": session_cookie,
                "Origin": "https://evil.example",
            },
            body={},
        )
        assert status == 403

        status, logout_headers, _ = _request(
            server,
            "POST",
            "/auth/logout",
            headers={"Cookie": session_cookie, "Origin": "https://gas.example.com"},
        )
        assert status == 204
        assert any("Max-Age=0" in value for value in logout_headers["Set-Cookie"])
        status, logged_out_headers, _ = _request(
            server,
            "GET",
            "/admin",
            headers={"Cookie": session_cookie},
        )
        assert status == 302
        assert logged_out_headers["Location"].startswith("/auth/login?next=")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_entra_login_configuration_builds_auth_code_client(monkeypatch):
    from governed_autonomy import http_api

    config = http_api.EntraOIDCConfig(
        tenant_id="11111111-1111-4111-8111-111111111111",
        client_id="22222222-2222-4222-8222-222222222222",
    )
    discovery = OIDCDiscoveryDocument(
        issuer=config.issuer,
        jwks_uri="https://login.microsoftonline.com/tenant/keys",
        authorization_endpoint="https://login.microsoftonline.com/tenant/authorize",
        token_endpoint="https://login.microsoftonline.com/tenant/token",
    )
    captured = {}

    class StoppedServer:
        server_address = ("127.0.0.1", 8000)

        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            pass

    monkeypatch.setattr(http_api, "configure_logging", lambda: None)
    monkeypatch.setattr(
        http_api, "discover_oidc_configuration", lambda issuer: discovery
    )
    monkeypatch.setattr(
        http_api,
        "entra_oidc_validator_from_discovery",
        lambda entra_config, *, discovery: "validator",
    )
    monkeypatch.setattr(http_api, "build_runtime_service", lambda: ("service", None, None))

    def create_server(service, **kwargs):
        captured.update(kwargs)
        return StoppedServer()

    monkeypatch.setattr(http_api, "create_server", create_server)
    http_api.main(
        [
            "--entra-tenant-id",
            config.tenant_id,
            "--entra-client-id",
            config.client_id,
            "--entra-client-secret",
            "secret-value",
            "--entra-redirect-uri",
            "https://gas.example.com/auth/callback",
        ]
    )
    assert captured["oidc_only"] is True
    assert captured["oidc_validator"] == "validator"
    assert captured["oidc_auth_client"].client_id == config.client_id
    assert captured["oidc_auth_client"].client_secret == "secret-value"
    assert captured["oidc_auth_client"].redirect_uri == "https://gas.example.com/auth/callback"
    assert captured["oidc_cookie_secure"] is True
