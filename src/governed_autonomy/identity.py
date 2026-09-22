"""Fail-closed OIDC/JWT validation with an injectable, rotatable JWKS source."""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any, Protocol
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
    ) -> None:
        if not issuer or not algorithms:
            raise ValueError("issuer and algorithms are required")
        self.issuer = issuer
        self.audience = (audience,) if isinstance(audience, str) else tuple(audience)
        if not self.audience:
            raise ValueError("audience is required")
        self.provider, self.algorithms, self.clock = jwks_provider, frozenset(algorithms), clock

    def validate(self, token: str) -> ExternalIdentity:
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
        if alg == "none" or alg not in self.algorithms or not kid:
            raise IdentityValidationError("JWT algorithm or key id is not trusted")
        if (
            claims.get("iss") != self.issuer
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"]
        ):
            raise IdentityValidationError("issuer or subject claim is invalid")
        aud = claims.get("aud")
        if not (
            aud in self.audience
            if isinstance(aud, str)
            else isinstance(aud, list) and any(x in self.audience for x in aud)
        ):
            raise IdentityValidationError("audience claim is invalid")
        now = float(self.clock())
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or now >= exp:
            raise IdentityValidationError("token is expired or has no expiry")
        if "nbf" in claims and (not isinstance(claims["nbf"], (int, float)) or now < claims["nbf"]):
            raise IdentityValidationError("token is not yet valid")
        if "iat" in claims and (
            not isinstance(claims["iat"], (int, float)) or claims["iat"] > now + 30
        ):
            raise IdentityValidationError("token issued-at is invalid")
        jwks = self.provider.get_jwks()
        keys = {item.get("kid"): item for item in jwks.get("keys", []) if isinstance(item, dict)}
        jwk = keys.get(kid)
        if jwk is None:  # providers may refresh their cache on rotation
            refresh = getattr(self.provider, "refresh", None)
            if callable(refresh):
                refresh()
            jwks = self.provider.get_jwks()
            keys = {
                item.get("kid"): item for item in jwks.get("keys", []) if isinstance(item, dict)
            }
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

    def validate_token(self, token: str) -> ExternalIdentity:
        """Explicit alias useful at HTTP middleware boundaries."""
        return self.validate(token)


JWTValidator = OIDCValidator
