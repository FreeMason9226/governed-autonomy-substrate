"""JWT validation facade with an opt-in, atomic one-time token replay guard."""

from __future__ import annotations

import base64
import json
import threading
import time
from typing import Any, Protocol

from ..identity import (
    ExternalIdentity,
    IdentityValidationError,
    OIDCValidator,
)
from .store import IdentityTokenReplayError


class JWTReplayCache:
    """Bounded process-local jti cache; inject a shared implementation for replicas."""

    def __init__(
        self,
        *,
        clock: Any = time.time,
        max_entries: int = 100_000,
        replay_store: JWTReplayStore | None = None,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._clock = clock
        self._max_entries = max_entries
        self._replay_store = replay_store
        self._lock = threading.RLock()
        self._expires: dict[tuple[str, str, str], float] = {}

    def consume(self, issuer: str, audience: tuple[str, ...], jti: str, expires_at: float) -> None:
        now = float(self._clock())
        if expires_at <= now:
            raise IdentityValidationError("replayed token has expired")
        key = (issuer, "|".join(sorted(audience)), jti)
        if self._replay_store is not None:
            try:
                self._replay_store.consume_token(issuer, key[1], jti, expires_at)
            except IdentityTokenReplayError as exc:
                raise IdentityValidationError("JWT token replay detected") from exc
            return
        with self._lock:
            self._expires = {
                entry: expiry for entry, expiry in self._expires.items() if expiry > now
            }
            if key in self._expires:
                raise IdentityValidationError("JWT token replay detected")
            if len(self._expires) >= self._max_entries:
                raise IdentityValidationError("JWT replay cache capacity is exhausted")
            self._expires[key] = expires_at


class JWTReplayStore(Protocol):
    def consume_token(
        self, issuer: str, audience: str, jti: str, expires_at: float
    ) -> None: ...


class JWTValidator:
    """Validates signature/issuer/audience/time through OIDCValidator.

    Normal bearer access tokens are reusable by design. Call ``validate_once``
    for one-time assertions; it requires a signed ``jti`` and atomically consumes it.
    """

    def __init__(self, validator: OIDCValidator, *, replay_cache: JWTReplayCache | None = None):
        self.validator = validator
        self.replay_cache = replay_cache or JWTReplayCache(clock=validator.clock)

    def validate(self, token: str, *, nonce: str | None = None) -> ExternalIdentity:
        return self.validator.validate(token, nonce=nonce)

    def validate_once(self, token: str, *, nonce: str | None = None) -> ExternalIdentity:
        identity = self.validator.validate(token, nonce=nonce)
        try:
            payload = token.split(".")[1]
            claims = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            )
        except (IndexError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise IdentityValidationError("malformed JWT") from exc
        jti = claims.get("jti")
        exp = claims.get("exp")
        if not isinstance(jti, str) or not jti:
            raise IdentityValidationError("one-time JWT is missing jti")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool):
            raise IdentityValidationError("one-time JWT is missing expiry")
        self.replay_cache.consume(self.validator.issuer, self.validator.audience, jti, float(exp))
        return identity
