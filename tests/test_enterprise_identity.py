import json
import threading
from http.client import HTTPConnection

import pytest

from governed_autonomy import (
    EntraDeviceAuthorizationClient,
    EntraOIDCConfig,
    ExternalIdentity,
    SQLiteIdentityStore,
    build_demo_service,
    create_server,
)
from governed_autonomy.auth.jwt_validator import JWTReplayCache
from governed_autonomy.identity import IdentityValidationError

TENANT = "11111111-1111-4111-8111-111111111111"
CLIENT = "22222222-2222-4222-8222-222222222222"


def test_entra_device_code_flow_uses_msal_and_returns_access_token():
    captured = {}

    class FakeMSALApplication:
        def __init__(self, *, client_id, authority):
            captured["client_id"] = client_id
            captured["authority"] = authority

        def initiate_device_flow(self, *, scopes):
            captured["scopes"] = scopes
            return {"user_code": "ABCD-EFGH", "device_code": "opaque", "message": "sign in"}

        def get_accounts(self):
            return []

        def acquire_token_silent(self, scopes, *, account):
            return None

        def acquire_token_by_device_flow(self, flow):
            captured["flow"] = flow
            return {"access_token": "signed-access-token"}

    messages = []
    token = EntraDeviceAuthorizationClient(
        EntraOIDCConfig(TENANT, CLIENT),
        scopes=["api://gas/access_as_user"],
        client_factory=FakeMSALApplication,
    ).acquire_token(output=messages.append)

    assert token["access_token"] == "signed-access-token"
    assert captured["authority"] == f"https://login.microsoftonline.com/{TENANT}"
    assert captured["scopes"] == ["api://gas/access_as_user"]
    assert captured["flow"]["device_code"] == "opaque"
    assert messages == ["sign in"]


def test_jwt_replay_cache_consumes_one_time_token_identifier():
    cache = JWTReplayCache(clock=lambda: 10)
    cache.consume("issuer", ("api",), "token-1", 20)
    with pytest.raises(IdentityValidationError, match="replay"):
        cache.consume("issuer", ("api",), "token-1", 20)


def test_identity_store_role_assignments_and_identity_events_persist(tmp_path):
    database = tmp_path / "identities.sqlite"
    store = SQLiteIdentityStore(database)
    store.assign_role("principal-1", "operator", "admin-1", tenant=TENANT)
    store.record_authentication(
        subject="principal-1",
        tenant=TENANT,
        email=None,
        display_name="worker",
        issuer=f"https://login.microsoftonline.com/{TENANT}/v2.0",
        roles=("operator", "service_principal"),
        identity_source="entra",
        service_principal=True,
        client_id=CLIENT,
    )
    assert store.roles_for("principal-1", TENANT) == ("operator",)
    assert store.roles_for("principal-1", "another-tenant") == ()
    assert store.service_principals()[0]["client_id"] == CLIENT
    event = store.identity_events()[0]
    assert event["details"]["subject"] == "principal-1"
    assert event["details"]["tenant"] == TENANT
    assert event["details"]["identity_source"] == "entra"
    assert event["details"]["roles"] == ["operator", "service_principal"]
    store.close()

    reopened = SQLiteIdentityStore(database, clock=lambda: 10)
    assert reopened.roles_for("principal-1", TENANT) == ("operator",)
    durable_replay_cache = JWTReplayCache(clock=lambda: 10, replay_store=reopened)
    durable_replay_cache.consume("issuer", ("api",), "single-use-token", 20)
    with pytest.raises(IdentityValidationError, match="replay"):
        durable_replay_cache.consume("issuer", ("api",), "single-use-token", 20)
    reopened.close()


def test_service_principal_with_assigned_operator_role_can_authorize():
    subject = "principal-object-id"
    store = SQLiteIdentityStore()
    store.assign_role(subject, "operator", "platform-admin", tenant=TENANT)

    class ServiceTokenValidator:
        def validate(self, token):
            assert token == "service-access-token"
            return ExternalIdentity(
                subject="token-subject",
                issuer=f"https://login.microsoftonline.com/{TENANT}/v2.0",
                claims={
                    "oid": subject,
                    "tid": TENANT,
                    "idtyp": "app",
                    "azp": CLIENT,
                    "roles": [],
                },
            )

    service, _, _ = build_demo_service()
    server = create_server(
        service,
        oidc_validator=ServiceTokenValidator(),
        oidc_only=True,
        identity_store=store,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = {
            "policy_id": "demo-files-v1",
            "request": {
                "action": "write_file",
                "path": "out.txt",
                "content": "authorized",
            },
        }
        body = json.dumps(payload).encode()
        connection = HTTPConnection(*server.server_address)
        connection.request(
            "POST",
            "/authorize",
            body=body,
            headers={
                "Authorization": "Bearer service-access-token",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
            },
        )
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()
        assert response.status == 200, result
        context = result["action_request"]["context"]
        assert context["subject"] == subject
        assert context["tenant_id"] == TENANT
        assert context["roles"] == ["operator", "service_principal"]
        assert context["issuer"] == f"https://login.microsoftonline.com/{TENANT}/v2.0"
        assert context["identity_source"] == "entra"
        assert context["service_principal"] is True
        identity_event = store.identity_events()[0]["details"]
        assert identity_event["subject"] == subject
        assert identity_event["tenant"] == TENANT
        assert identity_event["roles"] == ["operator", "service_principal"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        store.close()
