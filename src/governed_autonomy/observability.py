from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .service import GovernedService


@dataclass
class RuntimeMetrics:
    service: str
    environment: str = "dev"
    total_authorizations: int = 0
    successful_authorizations: int = 0
    denied_authorizations: int = 0
    total_executions: int = 0
    successful_executions: int = 0
    failed_executions: int = 0
    last_updated_at: int = field(default_factory=lambda: int(time.time()))

    def record_authorized(self) -> None:
        self.total_authorizations += 1
        self.successful_authorizations += 1
        self.last_updated_at = int(time.time())

    def record_denied(self) -> None:
        self.total_authorizations += 1
        self.denied_authorizations += 1
        self.last_updated_at = int(time.time())

    def record_execution(self, *, ok: bool) -> None:
        self.total_executions += 1
        if ok:
            self.successful_executions += 1
        else:
            self.failed_executions += 1
        self.last_updated_at = int(time.time())

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "total_authorizations": self.total_authorizations,
            "successful_authorizations": self.successful_authorizations,
            "denied_authorizations": self.denied_authorizations,
            "total_executions": self.total_executions,
            "successful_executions": self.successful_executions,
            "failed_executions": self.failed_executions,
            "last_updated_at": self.last_updated_at,
        }


class PlatformObservability:
    """Runtime monitoring for the governance barrier and platform shell."""

    def __init__(
        self, *, service: GovernedService, service_name: str, environment: str = "dev"
    ) -> None:
        self.service = service
        self.metrics = RuntimeMetrics(service=service_name, environment=environment)

    def record_authorized(self) -> None:
        self.metrics.record_authorized()

    def record_denied(self) -> None:
        self.metrics.record_denied()

    def record_execution(self, *, ok: bool) -> None:
        self.metrics.record_execution(ok=ok)

    def snapshot(self) -> dict[str, Any]:
        return {
            "metrics": self.metrics.to_dict(),
            "health": self.service.audit_report()["health"],
            "actions": sorted(self.service.actions),
            "policy_ids": sorted(self.service.policies.versions()),
        }

    def export_audit_bundle(self) -> dict[str, Any]:
        report = self.service.audit_report()
        return {
            "service": self.metrics.service,
            "environment": self.metrics.environment,
            "metrics": self.metrics.to_dict(),
            "audit": report,
            "generated_at": int(time.time()),
        }

    def prometheus(self) -> str:
        values = self.metrics.to_dict()
        lines = []
        for key in (
            "total_authorizations",
            "successful_authorizations",
            "denied_authorizations",
            "total_executions",
            "successful_executions",
            "failed_executions",
        ):
            lines.append(
                f'governed_autonomy_{key}{{service="{self.metrics.service}",environment="{self.metrics.environment}"}} {values[key]}'
            )
        return "\n".join(lines) + "\n"

    def trace_hook(self, event: str, attributes: dict[str, Any]) -> None:
        """No-op OpenTelemetry-compatible hook for deployment instrumentation."""
        if not event or not isinstance(attributes, dict):
            raise ValueError("event and attributes are required")
