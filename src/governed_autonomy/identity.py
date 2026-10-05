"""Fail-closed OIDC/JWT validation with an injectable, rotatable JWKS source."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import math
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384, SHA512


class IdentityValidationError(ValueError):
    """Raised for any malformed, untrusted, or expired identity token."""


class JWKSProvider(Protocol):
    def get_jwks(self) -> dict[str, Any]: ...


class StaticJWKSProvider:
    def __init__(self, jwks: dict[str, Any]) -> None:
        self._jwks = jwks

    def get_jwks(self) -> dict[str, Any]:
        return self._jwks

    def rotate(self, jwks: dict[str, Any]) -> None:
        self._jwks = jwks


_PRIVATE_JWK_FIELDS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_MAX_JWKS_BYTES = 1024 * 1024
_MAX_OIDC_METADATA_BYTES = 1024 * 1024


def _signing_keys_by_id(jwks: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_keys = jwks.get("keys")
    if not isinstance(raw_keys, list):
        raise IdentityValidationError("JWKS document is invalid")
    keys: dict[str, dict[str, Any]] = {}
    for item in raw_keys:
        if not isinstance(item, dict) or _PRIVATE_JWK_FIELDS.intersection(item):
            raise IdentityValidationError("JWKS must contain public keys only")
        if item.get("use", "sig") != "sig":
            continue
        key_ops = item.get("key_ops")
        if key_ops is not None and (
            not isinstance(key_ops, list) or "verify" not in key_ops
        ):
            continue
        kid = item.get("kid")
        if not isinstance(kid, str) or not kid:
            raise IdentityValidationError("JWKS signing key is missing a key id")
        if kid in keys:
            raise IdentityValidationError("JWKS contains duplicate signing key ids")
        keys[kid] = item
    return keys


class UrlJWKSProvider:
    """Fetch and cache JWKS documents from an operator-approved HTTPS endpoint."""

    def __init__(
        self,
        url: str,
        *,
        cache_seconds: int = 300,
        timeout_seconds: int = 5,
        clock: Any = time.monotonic,
    ) -> None:
        if not url.startswith("https://"):
            raise ValueError("JWKS URL must use HTTPS")
        if cache_seconds <= 0 or timeout_seconds <= 0:
            raise ValueError("JWKS cache and timeout must be positive")
        self.url = url
        self.cache_seconds = cache_seconds
        self.timeout_seconds = timeout_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._jwks: dict[str, Any] | None = None
        self._expires_at = 0.0
        self._last_rotated_at = 0.0
        self._key_fingerprint: str | None = None

    def get_jwks(self) -> dict[str, Any]:
        with self._lock:
            if self._jwks is None or self._clock() >= self._expires_at:
                self._refresh_locked()
            if self._jwks is None:
                raise IdentityValidationError("JWKS document is unavailable")
            return copy.deepcopy(self._jwks)

    def refresh(self) -> None:
        with self._lock:
            self._refresh_locked()

    def _refresh_locked(self) -> None:
        request = Request(self.url, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310
                raw_document = response.read(_MAX_JWKS_BYTES + 1)
            if len(raw_document) > _MAX_JWKS_BYTES:
                raise IdentityValidationError("JWKS document exceeds the maximum size")
            document = json.loads(raw_document)
        except IdentityValidationError:
            raise
        except Exception as exc:
            raise IdentityValidationError("JWKS endpoint is unavailable") from exc
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise IdentityValidationError("JWKS document is invalid")
        current_keys = _signing_keys_by_id(document)
        fingerprint = hashlib.sha256(
            json.dumps(current_keys, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        now = self._clock()
        if self._key_fingerprint is not None and fingerprint != self._key_fingerprint:
            self._last_rotated_at = time.time()
        self._jwks = copy.deepcopy(document)
        self._expires_at = now + self.cache_seconds
        self._key_fingerprint = fingerprint

    @property
    def last_rotated_at(self) -> float:
        """Unix timestamp of the last observed change in the JWKS key set (0.0 if none yet)."""
        with self._lock:
            return self._last_rotated_at


@dataclass(frozen=True)
class OIDCDiscoveryDocument:
    issuer: str
    jwks_uri: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    supported_signing_algorithms: tuple[str, ...] = ()
    raw: dict[str, Any] | None = None


def discover_oidc_configuration(
    issuer: str, *, timeout_seconds: int = 5
) -> OIDCDiscoveryDocument:
    """Fetch and validate an OIDC ``.well-known/openid-configuration`` document.

    Fails closed: any network error, malformed JSON, missing ``jwks_uri``, or an
    ``issuer`` field that does not match the requested issuer raises
    ``IdentityValidationError`` rather than returning a partial/unsafe result.
    """
    if not issuer.startswith("https://"):
        raise ValueError("OIDC issuer must use HTTPS")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    discovery_url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    request = Request(discovery_url, headers={"Accept": "application/json"})
    try:
        with urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            raw_document = response.read(_MAX_OIDC_METADATA_BYTES + 1)
        if len(raw_document) > _MAX_OIDC_METADATA_BYTES:
            raise IdentityValidationError("OIDC discovery document exceeds the maximum size")
        document = json.loads(raw_document)
    except IdentityValidationError:
        raise
    except Exception as exc:
        raise IdentityValidationError("OIDC discovery endpoint is unavailable") from exc
    if not isinstance(document, dict):
        raise IdentityValidationError("OIDC discovery document is invalid")
    discovered_issuer = document.get("issuer")
    jwks_uri = document.get("jwks_uri")
    if not isinstance(discovered_issuer, str) or discovered_issuer != issuer:
        raise IdentityValidationError("OIDC discovery document issuer mismatch")
    if not isinstance(jwks_uri, str) or not jwks_uri.startswith("https://"):
        raise IdentityValidationError("OIDC discovery document is missing a valid jwks_uri")
    authorization_endpoint = document.get("authorization_endpoint")
    token_endpoint = document.get("token_endpoint")
    for name, endpoint in (
        ("authorization_endpoint", authorization_endpoint),
        ("token_endpoint", token_endpoint),
    ):
        if endpoint is not None and (
            not isinstance(endpoint, str) or not endpoint.startswith("https://")
        ):
            raise IdentityValidationError(f"OIDC discovery document has an invalid {name}")
    raw_algorithms = document.get("id_token_signing_alg_values_supported")
    if raw_algorithms is None:
        supported_algorithms: tuple[str, ...] = ()
    elif isinstance(raw_algorithms, list) and all(
        isinstance(algorithm, str) and algorithm and algorithm != "none"
        for algorithm in raw_algorithms
    ):
        supported_algorithms = tuple(dict.fromkeys(raw_algorithms))
        if not supported_algorithms:
            raise IdentityValidationError("OIDC discovery document has no supported signing algorithms")
    else:
        raise IdentityValidationError(
            "OIDC discovery document has an invalid supported signing algorithms list"
        )
    return OIDCDiscoveryDocument(
        issuer=discovered_issuer,
        jwks_uri=jwks_uri,
        authorization_endpoint=authorization_endpoint,
        token_endpoint=token_endpoint,
        supported_signing_algorithms=supported_algorithms,
        raw=document,
    )


def oidc_validator_from_discovery(
    *,
    issuer: str,
    audience: str | tuple[str, ...],
    tenant_id: str | None = None,
    discovery: OIDCDiscoveryDocument | None = None,
    algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA"),
    cache_seconds: int = 300,
    timeout_seconds: int = 5,
    clock: Any = time.time,
) -> OIDCValidator:
    """Build an ``OIDCValidator`` by resolving the JWKS endpoint via OIDC discovery.

    This lets operators configure only the issuer (and audience) instead of a
    hardcoded JWKS URL, so key rotation and JWKS endpoint changes on the
    identity provider side require no redeployment.
    """
    discovery = discovery or discover_oidc_configuration(issuer, timeout_seconds=timeout_seconds)
    accepted_algorithms = algorithms
    if discovery.supported_signing_algorithms:
        accepted_algorithms = tuple(
            algorithm
            for algorithm in algorithms
            if algorithm in discovery.supported_signing_algorithms
        )
        if not accepted_algorithms:
            raise IdentityValidationError(
                "OIDC provider has no signing algorithm allowed by this validator"
            )
    jwks_provider = UrlJWKSProvider(
        discovery.jwks_uri, cache_seconds=cache_seconds, timeout_seconds=timeout_seconds
    )
    return OIDCValidator(
        issuer=issuer,
        audience=audience,
        jwks_provider=jwks_provider,
        algorithms=accepted_algorithms,
        clock=clock,
        tenant_id=tenant_id,
    )


@dataclass(frozen=True)
class EntraOIDCConfig:
    """Single-tenant Microsoft Entra ID settings for validating API access tokens."""

    tenant_id: str
    client_id: str

    def __post_init__(self) -> None:
        for name, value in (("tenant_id", self.tenant_id), ("client_id", self.client_id)):
            try:
                normalized = str(uuid.UUID(value))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError(f"{name} must be a Microsoft Entra GUID") from exc
            object.__setattr__(self, name, normalized)

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def audience(self) -> str:
        return self.client_id


def entra_oidc_validator_from_discovery(
    config: EntraOIDCConfig,
    *,
    discovery: OIDCDiscoveryDocument | None = None,
    algorithms: tuple[str, ...] = ("RS256",),
    cache_seconds: int = 300,
    timeout_seconds: int = 5,
    clock: Any = time.time,
) -> OIDCValidator:
    """Build a tenant-bound Entra validator using Microsoft OIDC discovery/JWKS."""
    return oidc_validator_from_discovery(
        issuer=config.issuer,
        audience=config.audience,
        tenant_id=config.tenant_id,
        discovery=discovery,
        algorithms=algorithms,
        cache_seconds=cache_seconds,
        timeout_seconds=timeout_seconds,
        clock=clock,
    )


class OIDCAuthCodeClient:
    """OIDC authorization-code client with PKCE for server-side token exchange."""

    def __init__(
        self,
        *,
        discovery: OIDCDiscoveryDocument,
        client_id: str,
        redirect_uri: str,
        client_secret: str | None = None,
        timeout_seconds: int = 5,
    ) -> None:
        if not client_id:
            raise ValueError("client_id is required")
        if not redirect_uri.startswith("https://"):
            raise ValueError("OIDC redirect URI must use HTTPS")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        authorization_endpoint = discovery.authorization_endpoint
        token_endpoint = discovery.token_endpoint
        if not authorization_endpoint or not token_endpoint:
            raise IdentityValidationError(
                "OIDC discovery document is missing authorization or token endpoint"
            )
        self.discovery = discovery
        self.authorization_endpoint = authorization_endpoint
        self.token_endpoint = token_endpoint
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.client_secret = client_secret
        self.timeout_seconds = timeout_seconds

    def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        parameters = urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "response_mode": "query",
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in self.authorization_endpoint else "?"
        return f"{self.authorization_endpoint}{separator}{parameters}"

    def exchange_code(self, *, code: str, code_verifier: str) -> dict[str, Any]:
        if not code or not code_verifier:
            raise ValueError("authorization code and PKCE verifier are required")
        parameters = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        }
        if self.client_secret:
            parameters["client_secret"] = self.client_secret
        request = Request(
            self.token_endpoint,
            data=urlencode(parameters).encode("ascii"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310
                raw_document = response.read(_MAX_JWKS_BYTES + 1)
            if len(raw_document) > _MAX_JWKS_BYTES:
                raise IdentityValidationError("OIDC token response exceeds the maximum size")
            document = json.loads(raw_document)
        except IdentityValidationError:
            raise
        except Exception as exc:
            raise IdentityValidationError("OIDC token endpoint is unavailable") from exc
        if (
            not isinstance(document, dict)
            or not isinstance(document.get("id_token"), str)
            or not document["id_token"]
        ):
            raise IdentityValidationError("OIDC token response is invalid")
        return document


def _b64(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise IdentityValidationError("invalid base64url value") from exc


def _jwk_key(jwk: dict[str, Any]) -> Any:
    kind = jwk.get("kty")
    try:
        if kind == "RSA":
            return rsa.RSAPublicNumbers(
                int.from_bytes(_b64(jwk["e"]), "big"), int.from_bytes(_b64(jwk["n"]), "big")
            ).public_key()
        if kind == "EC" and jwk.get("crv") in {"P-256", "P-384", "P-521"}:
            curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(), "P-521": ec.SECP521R1()}[
                jwk["crv"]
            ]
            return ec.EllipticCurvePublicKey.from_encoded_point(
                curve, b"\x04" + _b64(jwk["x"]) + _b64(jwk["y"])
            )
        if kind == "OKP" and jwk.get("crv") == "Ed25519":
            return ed25519.Ed25519PublicKey.from_public_bytes(_b64(jwk["x"]))
    except (KeyError, ValueError, TypeError) as exc:
        raise IdentityValidationError("invalid JWK") from exc
    raise IdentityValidationError("unsupported JWK key type")


@dataclass(frozen=True)
class ExternalIdentity:
    subject: str
    issuer: str
    claims: dict[str, Any]


class OIDCValidator:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str | tuple[str, ...],
        jwks_provider: JWKSProvider,
        algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA"),
        clock: Any = time.time,
        tenant_id: str | None = None,
    ) -> None:
        if not issuer or not algorithms:
            raise ValueError("issuer and algorithms are required")
        self.issuer = issuer
        self.audience = (audience,) if isinstance(audience, str) else tuple(audience)
        if not self.audience:
            raise ValueError("audience is required")
        self.tenant_id = tenant_id
        self.provider, self.algorithms, self.clock = jwks_provider, frozenset(algorithms), clock

    def validate(self, token: str, *, nonce: str | None = None) -> ExternalIdentity:
        if not isinstance(token, str) or not token:
            raise IdentityValidationError("token must be a non-empty string")
        try:
            header_raw, payload_raw, signature_raw = token.split(".")
            header = json.loads(_b64(header_raw))
            claims = json.loads(_b64(payload_raw))
            signing_input = f"{header_raw}.{payload_raw}".encode("ascii")
            signature = _b64(signature_raw)
        except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IdentityValidationError("malformed JWT") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise IdentityValidationError("JWT objects are invalid")
        alg, kid = header.get("alg"), header.get("kid")
        if (
            not isinstance(alg, str)
            or alg == "none"
            or alg not in self.algorithms
            or not isinstance(kid, str)
            or not kid
        ):
            raise IdentityValidationError("JWT algorithm or key id is not trusted")
        if (
            claims.get("iss") != self.issuer
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"]
        ):
            raise IdentityValidationError("issuer or subject claim is invalid")
        if self.tenant_id is not None and claims.get("tid") != self.tenant_id:
            raise IdentityValidationError("tenant claim is invalid")
        if nonce is not None and (
            not isinstance(claims.get("nonce"), str)
            or not secrets.compare_digest(claims["nonce"], nonce)
        ):
            raise IdentityValidationError("token nonce is invalid")
        aud = claims.get("aud")
        if not (
            aud in self.audience
            if isinstance(aud, str)
            else isinstance(aud, list) and any(x in self.audience for x in aud)
        ):
            raise IdentityValidationError("audience claim is invalid")
        now = float(self.clock())
        exp = claims.get("exp")
        if (
            not isinstance(exp, (int, float))
            or isinstance(exp, bool)
            or not math.isfinite(exp)
            or now >= exp
        ):
            raise IdentityValidationError("token is expired or has no expiry")
        if "nbf" in claims:
            not_before = claims["nbf"]
            if (
                not isinstance(not_before, (int, float))
                or isinstance(not_before, bool)
                or not math.isfinite(not_before)
                or now < not_before
            ):
                raise IdentityValidationError("token is not yet valid")
        if "iat" in claims and (
            not isinstance(claims["iat"], (int, float))
            or isinstance(claims["iat"], bool)
            or not math.isfinite(claims["iat"])
            or claims["iat"] > now + 30
        ):
            raise IdentityValidationError("token issued-at is invalid")
        jwks = self.provider.get_jwks()
        if not isinstance(jwks, dict):
            raise IdentityValidationError("JWKS document is invalid")
        keys = _signing_keys_by_id(jwks)
        jwk = keys.get(kid)
        if jwk is None:  # providers may refresh their cache on rotation
            refresh = getattr(self.provider, "refresh", None)
            if callable(refresh):
                refresh()
            jwks = self.provider.get_jwks()
            if not isinstance(jwks, dict):
                raise IdentityValidationError("JWKS document is invalid")
            keys = _signing_keys_by_id(jwks)
            jwk = keys.get(kid)
        if jwk is None or jwk.get("alg", alg) != alg:
            raise IdentityValidationError("signing key is not trusted")
        key = _jwk_key(jwk)
        try:
            if alg.startswith("RS"):
                key.verify(
                    signature,
                    signing_input,
                    padding.PKCS1v15(),
                    {"RS256": SHA256(), "RS384": SHA384(), "RS512": SHA512()}[alg],
                )
            elif alg.startswith("ES"):
                if len(signature) % 2:
                    raise IdentityValidationError("invalid ECDSA signature")
                half = len(signature) // 2
                signature = encode_dss_signature(
                    int.from_bytes(signature[:half], "big"), int.from_bytes(signature[half:], "big")
                )
                key.verify(
                    signature,
                    signing_input,
                    {
                        "ES256": ec.ECDSA(SHA256()),
                        "ES384": ec.ECDSA(SHA384()),
                        "ES512": ec.ECDSA(SHA512()),
                    }[alg],
                )
            elif alg == "EdDSA":
                key.verify(signature, signing_input)
            else:
                raise IdentityValidationError("unsupported JWT algorithm")
        except (InvalidSignature, KeyError, ValueError, TypeError) as exc:
            raise IdentityValidationError("JWT signature is invalid") from exc
        return ExternalIdentity(claims["sub"], self.issuer, claims)

    async def validate_async(
        self, token: str, *, nonce: str | None = None
    ) -> ExternalIdentity:
        """Validate without blocking an async caller's event loop."""
        return await asyncio.to_thread(self.validate, token, nonce=nonce)

    def validate_token(self, token: str) -> ExternalIdentity:
        """Explicit alias useful at HTTP middleware boundaries."""
        return self.validate(token)


JWTValidator = OIDCValidator
