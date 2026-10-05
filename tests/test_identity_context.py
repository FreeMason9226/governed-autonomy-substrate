import json
import threading
from http.client import HTTPConnection

from governed_autonomy import ExternalIdentity, RuntimeIdentity, build_demo_service, create_server


def test_runtime_identity_normalizes_validated_oidc_claims():
    identity = RuntimeIdentity.from_external_identity(
        ExternalIdentity(
            subject="user-42",
            issuer="https://identity.example",
            claims={
                "tid": "tenant-7",
                "name": "A. User",
                "preferred_username": "user@example.com",
                "roles": ["gas-admin"],
                "groups": ["security-reviewers"],
            },
        ),
        request_id="request-1",
    )

    assert identity.subject == "user-42"
    assert identity.tenant == "tenant-7"
    assert identity.name == "A. User"
    assert identity.email == "user@example.com"
    assert identity.roles == ("operator",)
    assert identity.groups == ("security-reviewers",)
    assert identity.context() == {
        "tenant_id": "tenant-7",
        "actor_id": "oidc:https://identity.example:user-42",
        "environment": "dev",
        "request_id": "request-1",
        "source": "api",
        "roles": ["operator"],
        "subject": "user-42",
        "name": "A. User",
        "email": "user@example.com",
        "groups": ["security-reviewers"],
    }


def test_oidc_identity_context_overrides_untrusted_request_context():
    class StubOIDCValidator:
        def validate(self, token):
            assert token == "valid-token"
            return ExternalIdentity(
                subject="tenant-user",
                issuer="https://identity.example",
                claims={
                    "tid": "tenant-trusted",
                    "name": "Trusted Name",
                    "email": "trusted@example.com",
                    "roles": ["operator"],
                    "groups": ["trusted-group"],
                },
            )

    service, _, _ = build_demo_service()
    server = create_server(
        service,
        bearer_token="unused",
        oidc_validator=StubOIDCValidator(),
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        payload = {
            "policy_id": "demo-files-v1",
            "request": {
                "action": "write_file",
                "path": "out.txt",
                "content": "governed",
                "context": {
                    "tenant_id": "attacker-tenant",
                    "actor_id": "attacker",
                    "roles": ["platform_admin"],
                    "groups": ["untrusted-group"],
                    "custom_context": "preserved",
                },
            },
        }
        connection = HTTPConnection(*server.server_address)
        body = json.dumps(payload).encode()
        connection.request(
            "POST",
            "/authorize",
            body=body,
            headers={
                "Authorization": "Bearer valid-token",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Request-ID": "identity-request",
            },
        )
        response = connection.getresponse()
        result = json.loads(response.read())
        connection.close()

        assert response.status == 200
        context = result["action_request"]["context"]
        assert context["tenant_id"] == "tenant-trusted"
        assert context["actor_id"] == "oidc:https://identity.example:tenant-user"
        assert context["roles"] == ["operator"]
        assert context["groups"] == ["trusted-group"]
        assert context["subject"] == "tenant-user"
        assert context["name"] == "Trusted Name"
        assert context["email"] == "trusted@example.com"
        assert context["custom_context"] == "preserved"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
