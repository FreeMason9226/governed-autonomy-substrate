"""Deployment-safe HTTP controls that remain framework independent."""

from __future__ import annotations

import re
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Protocol


class RateLimiter(Protocol):
    def allow(self, client: str) -> bool: ...


@dataclass(frozen=True)
class TLSConfig:
    certfile: str
    keyfile: str
    min_version: str = "TLSv1.2"


class BoundedRateLimiter:
    def __init__(
        self, limit: int = 60, window_seconds: float = 60.0, max_clients: int = 10000
    ) -> None:
        if limit <= 0 or window_seconds <= 0 or max_clients <= 0:
            raise ValueError("rate limiter bounds must be positive")
        self.limit, self.window_seconds, self.max_clients = limit, window_seconds, max_clients
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            if client not in self._hits and len(self._hits) >= self.max_clients:
                return False
            hits = [
                stamp for stamp in self._hits.get(client, []) if now - stamp < self.window_seconds
            ]
            if len(hits) >= self.limit:
                self._hits[client] = hits
                return False
            hits.append(now)
            self._hits[client] = hits
            return True


class PostgresRateLimiter:
    """Shared sliding-window rate limiter for stateless API replicas."""

    def __init__(
        self,
        connection: Any,
        *,
        limit: int = 60,
        window_seconds: int = 60,
        namespace: str = "http",
    ) -> None:
        if limit <= 0 or window_seconds <= 0 or not namespace:
            raise ValueError("rate limiter bounds and namespace must be positive")
        self.connection = connection
        self.limit = limit
        self.window_seconds = window_seconds
        self.namespace = namespace
        cursor = self.connection.cursor()
        try:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS gas_rate_limit_hits (
                    namespace TEXT NOT NULL,
                    client_key TEXT NOT NULL,
                    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS gas_rate_limit_window_idx "
                "ON gas_rate_limit_hits(namespace, client_key, observed_at)"
            )
            self.connection.commit()
        finally:
            cursor.close()

    def allow(self, client: str) -> bool:
        if not client:
            return False
        cursor = self.connection.cursor()
        try:
            cursor.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (f"{self.namespace}:{client}",))
            cursor.execute(
                "DELETE FROM gas_rate_limit_hits WHERE observed_at < "
                "CURRENT_TIMESTAMP - (%s * INTERVAL '1 second')",
                (self.window_seconds,),
            )
            cursor.execute(
                "SELECT count(*) FROM gas_rate_limit_hits "
                "WHERE namespace=%s AND client_key=%s",
                (self.namespace, client),
            )
            allowed = int(cursor.fetchone()[0]) < self.limit
            if allowed:
                cursor.execute(
                    "INSERT INTO gas_rate_limit_hits(namespace, client_key) VALUES (%s, %s)",
                    (self.namespace, client),
                )
            self.connection.commit()
            return allowed
        except Exception:
            self.connection.rollback()
            return False
        finally:
            cursor.close()


def correlation_id(value: str | None = None) -> str:
    if value and re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value):
        return value
    return uuid.uuid4().hex


def security_headers() -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Cache-Control": "no-store",
    }


def validate_server_config(
    *,
    bearer_token: str | None,
    max_body_bytes: int,
    rate_limit: int,
    require_tls: bool = False,
    tls: TLSConfig | None = None,
) -> None:
    """Validate deploy-time settings before binding a listener."""
    if not bearer_token:
        raise ValueError("an explicit bearer token or OIDC integration is required")
    if max_body_bytes <= 0 or rate_limit <= 0:
        raise ValueError("body and rate limits must be positive")
    if require_tls and tls is None:
        raise ValueError("TLS configuration is required")
