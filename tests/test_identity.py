"""Tests for OIDC discovery and JWKS rotation behavior in governed_autonomy.identity."""

from __future__ import annotations

import json
from io import BytesIO

import pytest

from governed_autonomy.identity import (
    IdentityValidationError,
    OIDCDiscoveryDocument,
    OIDCValidator,
    UrlJWKSProvider,
    discover_oidc_configuration,
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
