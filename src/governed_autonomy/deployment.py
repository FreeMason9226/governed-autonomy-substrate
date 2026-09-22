"""Deployment-safe HTTP controls that remain framework independent."""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass


@dataclass(frozen=True)
class TLSConfig:
    certfile: str
    keyfile: str
    min_version: str = "TLSv1.2"


class BoundedRateLimiter:
    def __init__(self, limit: int = 60, window_seconds: float = 60.0, max_clients: int = 10000) -> None:
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
            hits = [stamp for stamp in self._hits.get(client, []) if now - stamp < self.window_seconds]
            if len(hits) >= self.limit:
                self._hits[client] = hits
                return False
            hits.append(now)
            self._hits[client] = hits
            return True


def correlation_id(value: str | None = None) -> str:
    return value if value and len(value) <= 128 and all(ch.isalnum() or ch in "-._" for ch in value) else uuid.uuid4().hex


def security_headers() -> dict[str, str]:
    return {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Cache-Control": "no-store",
    }


def validate_server_config(*, bearer_token: str | None, max_body_bytes: int,
                           rate_limit: int, require_tls: bool = False,
                           tls: TLSConfig | None = None) -> None:
    """Validate deploy-time settings before binding a listener."""
    if not bearer_token:
        raise ValueError("an explicit bearer token or OIDC integration is required")
    if max_body_bytes <= 0 or rate_limit <= 0:
        raise ValueError("body and rate limits must be positive")
    if require_tls and tls is None:
        raise ValueError("TLS configuration is required")
