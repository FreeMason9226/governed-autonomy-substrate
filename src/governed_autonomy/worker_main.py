"""``gas-worker``: poll the Postgres job queue and run authorized jobs in a sandbox.

Configuration (environment):
  DATABASE_URL, GAS_ISSUER_KEY_ID / GAS_ISSUER_PRIVATE_KEY (runtime service, as the API),
  GAS_WORKER_IMAGES   comma-separated allow-listed container images (required)
  VAULT_ADDR, VAULT_TOKEN   optional; enables secret injection
  GAS_WORKER_POLL_SECONDS   idle sleep (default 2)
  GAS_WORKER_METRICS_PORT   optional; serves Prometheus /metrics (host: GAS_WORKER_METRICS_HOST)

Job payload: ``{"artifact": "<GAA json>"}``. The signed artifact's action request supplies
``image``, ``command`` and optional ``policy_id``/``required_secrets``; the artifact is
verified and consumed through the execution barrier, so replays are rejected.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .bootstrap import build_runtime_service
from .jobs import JobStore
from .service import GovernedService
from .worker import (
    ContainerSandbox,
    SecretProvider,
    VaultSecretProvider,
    WorkerMetrics,
    WorkerRuntime,
)


class _NoSecrets:
    def fetch(self, policy_id: str, required_keys: Any) -> dict[str, str]:
        raise RuntimeError("no secret provider configured (set VAULT_ADDR and VAULT_TOKEN)")


def make_authorizer(service: GovernedService) -> Callable[[dict[str, Any]], dict[str, Any]]:
    """Authorize via the signed artifact only; the service action must return the job spec."""

    def authorize(payload: dict[str, Any]) -> dict[str, Any]:
        artifact = payload.get("artifact")
        if not isinstance(artifact, str):
            raise ValueError("job payload must carry a signed artifact")
        result = service.execute_json(artifact)
        if not isinstance(result, dict):
            raise ValueError("authorized action did not return a job spec")
        return result

    return authorize


def start_metrics_server(
    metrics: WorkerMetrics, port: int, host: str = "127.0.0.1"
) -> ThreadingHTTPServer:
    """Serve ``GET /metrics`` (Prometheus text) from a daemon thread."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/metrics":
                self.send_error(404)
                return
            body = metrics.prometheus().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def serve(
    worker: WorkerRuntime,
    *,
    poll_seconds: float = 2.0,
    should_stop: Callable[[], bool] = lambda: False,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    processed = 0
    while not should_stop():
        if worker.process_once() is None:
            sleep(poll_seconds)
        else:
            processed += 1
    return processed


def main() -> int:
    images = [i.strip() for i in os.environ.get("GAS_WORKER_IMAGES", "").split(",") if i.strip()]
    if not images:
        raise SystemExit("GAS_WORKER_IMAGES is required")
    try:
        import psycopg
    except ImportError as exc:
        raise SystemExit("install the postgres extra: pip install .[postgres]") from exc
    from .jobs_postgres import PostgresJobStore

    service, _, replay_log = build_runtime_service()
    store: JobStore = PostgresJobStore(
        getattr(replay_log, "connection", None) or psycopg.connect(os.environ["DATABASE_URL"])
    )
    secrets: SecretProvider = _NoSecrets()
    if os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN"):
        secrets = VaultSecretProvider(os.environ["VAULT_ADDR"], os.environ["VAULT_TOKEN"])
    worker = WorkerRuntime(
        store,
        authorizer=make_authorizer(service),
        secrets=secrets,
        sandbox=ContainerSandbox(images),
    )
    port = os.environ.get("GAS_WORKER_METRICS_PORT")
    if port:
        start_metrics_server(
            worker.metrics, int(port), os.environ.get("GAS_WORKER_METRICS_HOST", "127.0.0.1")
        )
    stop = False

    def _stop(*_: Any) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    serve(
        worker,
        poll_seconds=float(os.environ.get("GAS_WORKER_POLL_SECONDS", "2")),
        should_stop=lambda: stop,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
