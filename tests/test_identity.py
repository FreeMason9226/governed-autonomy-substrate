"""Tests for OIDC discovery and JWKS rotation behavior in governed_autonomy.identity."""

from __future__ import annotations

import asyncio
import base64
import json
from io import BytesIO
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from governed_autonomy.identity import (
    EntraOIDCConfig,
    IdentityValidationError,
    OIDCAuthCodeClient,
    OIDCDiscoveryDocument,
    OIDCValidator,
    StaticJWKSProvider,
    UrlJWKSProvider,
    discover_oidc_configuration,
    entra_oidc_validator_from_discovery,
    oidc_validator_from_discovery,
)


class _FakeResponse(BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False


def _fake_urlopen_factory(payloads_by_url: dict[str, object]):
    def _fake_urlopen(request, timeout=5):  # noqa: ARG001 - signature parity with urllib
        url = request.full_url
        if url not in payloads_by_url:
            raise AssertionError(f"unexpected request to {url}")
        payload = payloads_by_url[url]
        if isinstance(payload, Exception):
            raise payload
        return _FakeResponse(json.dumps(payload).encode("utf-8"))

    return _fake_urlopen


ISSUER = "https://issuer.example.com"
JWKS_URL = "https://issuer.example.com/.well-known/jwks.json"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"


def test_discover_oidc_configuration_returns_validated_document(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory(
            {
                DISCOVERY_URL: {
                    "issuer": ISSUER,
                    "jwks_uri": JWKS_URL,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "id_token_signing_alg_values_supported": ["RS256", "RS384"],
                }
            }
        ),
    )
    document = discover_oidc_configuration(ISSUER)
    assert document == OIDCDiscoveryDocument(
        issuer=ISSUER,
        jwks_uri=JWKS_URL,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
        supported_signing_algorithms=("RS256", "RS384"),
        raw=document.raw,
    )


def test_discover_oidc_configuration_requires_https_issuer():
    with pytest.raises(ValueError):
        discover_oidc_configuration("http://issuer.example.com")


def test_discover_oidc_configuration_rejects_issuer_mismatch(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory(
            {DISCOVERY_URL: {"issuer": "https://not-the-issuer.example.com", "jwks_uri": JWKS_URL}}
        ),
    )
    with pytest.raises(IdentityValidationError):
        discover_oidc_configuration(ISSUER)


def test_discover_oidc_configuration_rejects_missing_jwks_uri(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory({DISCOVERY_URL: {"issuer": ISSUER}}),
    )
    with pytest.raises(IdentityValidationError):
        discover_oidc_configuration(ISSUER)


@pytest.mark.parametrize(
    "metadata",
    [
        {"issuer": ISSUER, "jwks_uri": JWKS_URL, "authorization_endpoint": "http://bad"},
        {
            "issuer": ISSUER,
            "jwks_uri": JWKS_URL,
            "token_endpoint": "http://bad",
        },
        {
            "issuer": ISSUER,
            "jwks_uri": JWKS_URL,
            "id_token_signing_alg_values_supported": [],
        },
        {
            "issuer": ISSUER,
            "jwks_uri": JWKS_URL,
            "id_token_signing_alg_values_supported": ["none", 3],
        },
    ],
)
def test_discover_oidc_configuration_rejects_invalid_metadata(monkeypatch, metadata):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory({DISCOVERY_URL: metadata}),
    )
    with pytest.raises(IdentityValidationError):
        discover_oidc_configuration(ISSUER)


def test_oidc_auth_code_client_builds_pkce_authorization_and_exchanges_code(monkeypatch):
    discovery = OIDCDiscoveryDocument(
        issuer=ISSUER,
        jwks_uri=JWKS_URL,
        authorization_endpoint=f"{ISSUER}/authorize",
        token_endpoint=f"{ISSUER}/token",
    )
    client = OIDCAuthCodeClient(
        discovery=discovery,
        client_id="entra-client",
        client_secret="client-secret",
        redirect_uri="https://gas.example.com/auth/callback",
    )
    authorization_url = client.authorization_url(
        state="state-123",
        nonce="nonce-456",
        code_challenge="challenge-789",
    )
    authorization_query = parse_qs(urlsplit(authorization_url).query)
    assert urlsplit(authorization_url).path == "/authorize"
    assert authorization_query["response_type"] == ["code"]
    assert authorization_query["response_mode"] == ["query"]
    assert authorization_query["scope"] == ["openid profile email"]
    assert authorization_query["state"] == ["state-123"]
    assert authorization_query["nonce"] == ["nonce-456"]
    assert authorization_query["code_challenge"] == ["challenge-789"]
    assert authorization_query["code_challenge_method"] == ["S256"]

    captured = {}

    def _fake_urlopen(request, timeout=5):  # noqa: ARG001
        captured["url"] = request.full_url
        captured["body"] = parse_qs(request.data.decode("ascii"))
        captured["content_type"] = request.get_header("Content-type")
        return _FakeResponse(b'{"id_token":"signed-id-token","token_type":"Bearer"}')

    monkeypatch.setattr("governed_autonomy.identity.urlopen", _fake_urlopen)
    response = client.exchange_code(code="authorization-code", code_verifier="verifier")
    assert captured["url"] == f"{ISSUER}/token"
    assert captured["content_type"] == "application/x-www-form-urlencoded"
    assert captured["body"] == {
        "client_id": ["entra-client"],
        "grant_type": ["authorization_code"],
        "code": ["authorization-code"],
        "redirect_uri": ["https://gas.example.com/auth/callback"],
        "code_verifier": ["verifier"],
        "client_secret": ["client-secret"],
    }
    assert response["id_token"] == "signed-id-token"


def test_oidc_auth_code_client_requires_secure_redirect_and_discovered_endpoints():
    with pytest.raises(ValueError, match="HTTPS"):
        OIDCAuthCodeClient(
            discovery=OIDCDiscoveryDocument(issuer=ISSUER, jwks_uri=JWKS_URL),
            client_id="client",
            redirect_uri="http://gas.example.com/auth/callback",
        )
    with pytest.raises(IdentityValidationError, match="authorization or token endpoint"):
        OIDCAuthCodeClient(
            discovery=OIDCDiscoveryDocument(issuer=ISSUER, jwks_uri=JWKS_URL),
            client_id="client",
            redirect_uri="https://gas.example.com/auth/callback",
        )


def test_discover_oidc_configuration_fails_closed_on_network_error(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory({DISCOVERY_URL: OSError("network down")}),
    )
    with pytest.raises(IdentityValidationError):
        discover_oidc_configuration(ISSUER)


def test_oidc_validator_from_discovery_builds_working_validator(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory(
            {
                DISCOVERY_URL: {"issuer": ISSUER, "jwks_uri": JWKS_URL},
                JWKS_URL: {"keys": []},
            }
        ),
    )
    validator = oidc_validator_from_discovery(issuer=ISSUER, audience="gas-api")
    assert isinstance(validator, OIDCValidator)
    assert validator.issuer == ISSUER
    assert isinstance(validator.provider, UrlJWKSProvider)
    assert validator.provider.url == JWKS_URL


def test_oidc_validator_from_discovery_restricts_algorithms_to_provider_metadata(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory(
            {
                DISCOVERY_URL: {
                    "issuer": ISSUER,
                    "jwks_uri": JWKS_URL,
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "id_token_signing_alg_values_supported": ["RS256", "HS256"],
                },
                JWKS_URL: {"keys": []},
            }
        ),
    )
    validator = oidc_validator_from_discovery(issuer=ISSUER, audience="gas-api")
    assert validator.algorithms == frozenset({"RS256"})
    with pytest.raises(IdentityValidationError, match="no signing algorithm"):
        oidc_validator_from_discovery(
            issuer=ISSUER, audience="gas-api", algorithms=("ES256",)
        )


def test_url_jwks_provider_tracks_last_rotated_at(monkeypatch):
    responses = iter(
        [
            {"keys": [{"kid": "k1"}]},
            {"keys": [{"kid": "k1"}]},
            {"keys": [{"kid": "k2"}]},
        ]
    )

    def _fake_urlopen(request, timeout=5):  # noqa: ARG001
        return _FakeResponse(json.dumps(next(responses)).encode("utf-8"))

    monkeypatch.setattr("governed_autonomy.identity.urlopen", _fake_urlopen)
    provider = UrlJWKSProvider(JWKS_URL, cache_seconds=1)
    assert provider.last_rotated_at == 0.0
    provider.refresh()
    assert provider.last_rotated_at == 0.0  # first fetch is not a rotation
    provider.refresh()
    assert provider.last_rotated_at == 0.0  # unchanged key set is not a rotation
    provider.refresh()
    assert provider.last_rotated_at > 0.0  # key set changed: rotation observed


def test_url_jwks_provider_caches_until_expiry_and_returns_detached_data(monkeypatch):
    calls = []
    now = [10.0]

    def _fake_urlopen(request, timeout=5):  # noqa: ARG001
        calls.append(request.full_url)
        return _FakeResponse(json.dumps({"keys": [{"kid": f"k{len(calls)}"}]}).encode())

    monkeypatch.setattr("governed_autonomy.identity.urlopen", _fake_urlopen)
    provider = UrlJWKSProvider(JWKS_URL, cache_seconds=30, clock=lambda: now[0])
    first = provider.get_jwks()
    first["keys"].clear()
    assert provider.get_jwks()["keys"][0]["kid"] == "k1"
    assert len(calls) == 1

    now[0] = 40
    assert provider.get_jwks()["keys"][0]["kid"] == "k2"
    assert len(calls) == 2
    assert provider.last_rotated_at > 0


def test_url_jwks_provider_detects_key_material_rotation_with_same_kid(monkeypatch):
    responses = iter(
        [
            {"keys": [{"kid": "stable-id", "kty": "RSA", "n": "AQ", "e": "Aw"}]},
            {"keys": [{"kid": "stable-id", "kty": "RSA", "n": "Ag", "e": "Aw"}]},
        ]
    )
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        lambda request, timeout=5: _FakeResponse(json.dumps(next(responses)).encode()),
    )
    provider = UrlJWKSProvider(JWKS_URL)
    provider.refresh()
    assert provider.last_rotated_at == 0
    provider.refresh()
    assert provider.last_rotated_at > 0


def test_url_jwks_provider_serializes_concurrent_cache_misses(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Lock

    calls = []
    calls_lock = Lock()

    def _fake_urlopen(request, timeout=5):  # noqa: ARG001
        with calls_lock:
            calls.append(request.full_url)
        return _FakeResponse(b'{"keys":[{"kid":"shared"}]}')

    monkeypatch.setattr("governed_autonomy.identity.urlopen", _fake_urlopen)
    provider = UrlJWKSProvider(JWKS_URL)
    with ThreadPoolExecutor(max_workers=8) as executor:
        documents = list(executor.map(lambda _: provider.get_jwks(), range(8)))
    assert len(calls) == 1
    assert all(document["keys"][0]["kid"] == "shared" for document in documents)


@pytest.mark.parametrize(
    "keys",
    [
        [{"kid": "private", "kty": "RSA", "n": "AQ", "e": "AQ", "d": "AQ"}],
        [{"kid": "duplicate"}, {"kid": "duplicate"}],
        [{"kid": "", "kty": "RSA"}],
    ],
)
def test_url_jwks_provider_rejects_invalid_or_private_signing_keys(monkeypatch, keys):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory({JWKS_URL: {"keys": keys}}),
    )
    provider = UrlJWKSProvider(JWKS_URL)
    with pytest.raises(IdentityValidationError):
        provider.get_jwks()


def test_url_jwks_provider_rejects_oversized_document(monkeypatch):
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        lambda request, timeout=5: _FakeResponse(
            b'{"keys":[]}' + b" " * (1024 * 1024 + 1)
        ),
    )
    with pytest.raises(IdentityValidationError, match="maximum size"):
        UrlJWKSProvider(JWKS_URL).get_jwks()


def test_url_jwks_provider_fails_closed_when_expired_cache_cannot_refresh(monkeypatch):
    now = [0.0]

    def _fake_urlopen(request, timeout=5):  # noqa: ARG001
        if now[0] >= 5:
            raise OSError("offline")
        return _FakeResponse(b'{"keys":[{"kid":"cached"}]}')

    monkeypatch.setattr("governed_autonomy.identity.urlopen", _fake_urlopen)
    provider = UrlJWKSProvider(JWKS_URL, cache_seconds=5, clock=lambda: now[0])
    assert provider.get_jwks()["keys"][0]["kid"] == "cached"
    now[0] = 5
    with pytest.raises(IdentityValidationError, match="unavailable"):
        provider.get_jwks()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unsigned_int_bytes(value: int) -> bytes:
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _signed_token(private_key, claims: dict[str, object]) -> str:
    header = _b64url(json.dumps({"alg": "RS256", "kid": "entra-key"}).encode())
    payload = _b64url(json.dumps(claims).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def test_entra_oidc_config_builds_tenant_issuer_and_api_audience():
    config = EntraOIDCConfig(
        tenant_id="11111111-1111-4111-8111-111111111111",
        client_id="22222222-2222-4222-8222-222222222222",
    )
    assert config.issuer == (
        "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0"
    )
    assert config.audience == "22222222-2222-4222-8222-222222222222"
    with pytest.raises(ValueError, match="tenant_id"):
        EntraOIDCConfig(tenant_id="common", client_id=config.client_id)


def test_entra_oidc_discovery_binds_tenant_and_validates_tenant_claim(monkeypatch):
    config = EntraOIDCConfig(
        tenant_id="11111111-1111-4111-8111-111111111111",
        client_id="22222222-2222-4222-8222-222222222222",
    )
    discovery_url = f"{config.issuer}/.well-known/openid-configuration"
    jwks_url = (
        "https://login.microsoftonline.com/"
        "11111111-1111-4111-8111-111111111111/discovery/v2.0/keys"
    )
    monkeypatch.setattr(
        "governed_autonomy.identity.urlopen",
        _fake_urlopen_factory(
            {discovery_url: {"issuer": config.issuer, "jwks_uri": jwks_url}, jwks_url: {"keys": []}}
        ),
    )
    validator = entra_oidc_validator_from_discovery(config)
    assert validator.tenant_id == config.tenant_id
    assert validator.audience == (config.client_id,)
    assert validator.provider.url == jwks_url

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    jwk = {
        "kid": "entra-key",
        "kty": "RSA",
        "n": _b64url(_unsigned_int_bytes(numbers.n)),
        "e": _b64url(_unsigned_int_bytes(numbers.e)),
        "alg": "RS256",
    }
    validator = OIDCValidator(
        issuer=config.issuer,
        audience=config.audience,
        tenant_id=config.tenant_id,
        jwks_provider=StaticJWKSProvider({"keys": [jwk]}),
        clock=lambda: 1000,
    )
    base_claims = {
        "iss": config.issuer,
        "sub": "user-42",
        "aud": config.audience,
        "exp": 2000,
        "tid": config.tenant_id,
    }
    identity = validator.validate(_signed_token(private_key, base_claims))
    assert identity.subject == "user-42"
    assert identity.claims["tid"] == config.tenant_id
    async_identity = asyncio.run(validator.validate_async(_signed_token(private_key, base_claims)))
    assert async_identity == identity
    nonce_claims = {**base_claims, "nonce": "expected-login-nonce"}
    assert validator.validate(
        _signed_token(private_key, nonce_claims),
        nonce="expected-login-nonce",
    ).subject == "user-42"
    with pytest.raises(IdentityValidationError, match="nonce"):
        validator.validate(_signed_token(private_key, base_claims), nonce="expected-login-nonce")
    with pytest.raises(IdentityValidationError, match="nonce"):
        validator.validate(
            _signed_token(private_key, nonce_claims),
            nonce="different-login-nonce",
        )

    wrong_tenant_claims = {**base_claims, "tid": "33333333-3333-4333-8333-333333333333"}
    with pytest.raises(IdentityValidationError, match="tenant claim"):
        validator.validate(_signed_token(private_key, wrong_tenant_claims))
    for claims, message in (
        ({**base_claims, "iss": "https://attacker.example"}, "issuer or subject"),
        ({**base_claims, "aud": "another-api"}, "audience"),
        ({**base_claims, "exp": 999}, "expired"),
        ({**base_claims, "exp": float("nan")}, "expired"),
    ):
        with pytest.raises(IdentityValidationError, match=message):
            validator.validate(_signed_token(private_key, claims))

    invalid_signature = _signed_token(private_key, base_claims).rsplit(".", 1)
    with pytest.raises(IdentityValidationError, match="signature"):
        validator.validate(f"{invalid_signature[0]}.{_b64url(b'not a valid signature')}")
    with pytest.raises(IdentityValidationError, match="non-empty string"):
        validator.validate("")
