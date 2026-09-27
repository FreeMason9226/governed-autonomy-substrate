from __future__ import annotations

import argparse
import os
import time
from dataclasses import dataclass
from typing import Any

from .api.app import _build_default_context
from .control_plane import ControlPlaneRepository


@dataclass(frozen=True)
class WorkerResult:
    authorization_id: str
    status: str
    attempts: int
    error: str | None = None


class WorkerService:
    def __init__(
        self,
        *,
        control_plane: ControlPlaneRepository,
        platform: Any,
        retry_delay_seconds: float = 1.0,
    ) -> None:
        self.control_plane = control_plane
        self.platform = platform
        self.retry_delay_seconds = retry_delay_seconds

    def run_once(self, *, now: float | None = None) -> WorkerResult | None:
        effective_now = time.time() if now is None else now
        ready = self.control_plane.list_ready_authorizations(now=effective_now, limit=1)
        if not ready:
            return None
        record = ready[0]
        artifact = record.artifact()
        if artifact is None:
            updated = self.control_plane.update_authorization(
                record.authorization_id,
                status="failed",
                error_text="authorization artifact is missing",
            )
            return WorkerResult(updated.authorization_id, updated.status, updated.execution_attempts, updated.error_text)
        if record.status == "cancelled":
            return WorkerResult(record.authorization_id, record.status, record.execution_attempts)
        if record.expires_at is not None and effective_now >= record.expires_at:
            updated = self.control_plane.update_authorization(
                record.authorization_id,
                status="expired",
                error_text="authorization expired before execution",
            )
            return WorkerResult(updated.authorization_id, updated.status, updated.execution_attempts, updated.error_text)
        attempts = record.execution_attempts + 1
        try:
            result = self.platform.execute(artifact)
        except Exception as exc:  # pragma: no cover - exercised via tests
            if attempts >= record.max_attempts:
                updated = self.control_plane.update_authorization(
                    record.authorization_id,
                    status="dead_letter",
                    execution_attempts=attempts,
                    error_text=str(exc),
                )
            else:
                updated = self.control_plane.update_authorization(
                    record.authorization_id,
                    status="authorized",
                    execution_attempts=attempts,
                    next_attempt_at=effective_now + self.retry_delay_seconds,
                    error_text=str(exc),
                )
            return WorkerResult(updated.authorization_id, updated.status, updated.execution_attempts, updated.error_text)
        updated = self.control_plane.update_authorization(
            record.authorization_id,
            status="executed",
            execution_attempts=attempts,
            next_attempt_at=None,
            result_payload=result,
            error_text=None,
        )
        return WorkerResult(updated.authorization_id, updated.status, updated.execution_attempts)

    def serve(self, *, poll_interval: float = 1.0) -> None:
        while True:
            self.run_once()
            time.sleep(poll_interval)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Governed Autonomy worker service.")
    parser.add_argument("--poll-interval", type=float, default=float(os.environ.get("GAS_WORKER_POLL_INTERVAL", "1.0")))
    parser.add_argument("--retry-delay", type=float, default=float(os.environ.get("GAS_WORKER_RETRY_DELAY", "1.0")))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    context = _build_default_context()
    worker = WorkerService(
        control_plane=context.control_plane,
        platform=context.platform,
        retry_delay_seconds=args.retry_delay,
    )
    try:
        worker.serve(poll_interval=args.poll_interval)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
