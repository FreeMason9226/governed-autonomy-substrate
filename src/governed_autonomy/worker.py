"""Sandboxed worker runtime for jobs persisted in :class:`SQLiteJobStore`.

Every job must pass an injected ``authorizer`` (typically a check against the
governance barrier) before secrets are fetched or a container is started. The
authorizer returns the *authorized* job spec, which replaces the queued payload,
so unsigned queue fields can never influence execution.
"""

from __future__ import annotations

import json
import re
import subprocess  # nosec B404
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from .jobs import Job, JobStore, run_once

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")


class SecretProvider(Protocol):
    def fetch(self, policy_id: str, required_keys: Sequence[str]) -> dict[str, str]: ...


class VaultSecretProvider:
    """HashiCorp Vault KV v2 reader scoped to ``<mount>/data/policies/<policy_id>``.

    Fails closed: any missing path or key raises rather than returning a partial set.
    """

    def __init__(
        self,
        addr: str,
        token: str,
        *,
        mount: str = "gas",
        timeout_seconds: float = 5.0,
        allow_insecure: bool = False,
    ) -> None:
        if not token:
            raise ValueError("vault token is required")
        if not addr.startswith("https://") and not allow_insecure:
            raise ValueError("Vault address must use HTTPS (or set allow_insecure for in-cluster)")
        self.addr, self._token = addr.rstrip("/"), token
        self.mount, self.timeout_seconds = mount, timeout_seconds

    def fetch(self, policy_id: str, required_keys: Sequence[str]) -> dict[str, str]:
        if not _SAFE_ID.match(policy_id):
            raise ValueError("invalid policy_id")
        url = f"{self.addr}/v1/{quote(self.mount)}/data/policies/{policy_id}"
        request = Request(url, headers={"X-Vault-Token": self._token})
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310
                document = json.loads(response.read())
        except (URLError, OSError, ValueError) as exc:
            raise RuntimeError("secret retrieval failed") from exc
        data = document.get("data", {}).get("data", {}) if isinstance(document, dict) else {}
        missing = [k for k in required_keys if k not in data]
        if missing:
            raise RuntimeError(f"required secrets not found: {', '.join(missing)}")
        return {k: str(data[k]) for k in required_keys}


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int
    output: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


Runner = Callable[..., Any]


class ContainerSandbox:
    """Runs one command in a locked-down container (no network, read-only, no caps).

    Only allow-listed images run. The command is an argv list (never a shell string)
    and secret *values* are passed through the child environment, not argv.
    """

    def __init__(
        self,
        allowed_images: Sequence[str],
        *,
        runtime: str = "docker",
        memory: str = "128m",
        cpus: str = "0.5",
        pids_limit: int = 64,
        runner: Runner = subprocess.run,
    ) -> None:
        if not allowed_images:
            raise ValueError("at least one allowed image is required")
        self.allowed_images = frozenset(allowed_images)
        self.runtime, self.memory, self.cpus = runtime, memory, cpus
        self.pids_limit, self._runner = pids_limit, runner

    def build_command(
        self, image: str, command: Sequence[str], secret_names: Sequence[str]
    ) -> list[str]:
        if image not in self.allowed_images:
            raise ValueError("image is not allow-listed")
        if not command or not all(isinstance(c, str) for c in command):
            raise ValueError("command must be a non-empty list of strings")
        argv = [
            self.runtime, "run", "--rm", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            f"--memory={self.memory}", f"--cpus={self.cpus}", f"--pids-limit={self.pids_limit}",
            "--user=10001:10001", "--tmpfs=/tmp:rw,noexec,nosuid,size=16m",
        ]  # fmt: skip
        for name in secret_names:
            if not _ENV_NAME.match(name):
                raise ValueError("invalid secret name")
            argv += ["-e", name]
        return [*argv, image, *command]

    def execute(
        self,
        image: str,
        command: Sequence[str],
        secrets: Mapping[str, str],
        timeout_seconds: float = 30.0,
    ) -> SandboxResult:
        argv = self.build_command(image, command, list(secrets))
        try:
            completed = self._runner(
                argv,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", **secrets},
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("sandbox execution timed out") from exc
        output = (completed.stdout or b"") + (completed.stderr or b"")
        text = output.decode("utf-8", "replace") if isinstance(output, bytes) else str(output)
        for value in secrets.values():
            if value:
                text = text.replace(value, "[REDACTED]")
        return SandboxResult(completed.returncode, text[:4096])


class WorkerMetrics:
    """Thread-safe job counters rendered in Prometheus text format."""

    _OUTCOMES = {
        "succeeded": "succeeded",
        "dead_letter": "dead_lettered",
        "queued": "retried",
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counts = {"processed": 0, "succeeded": 0, "retried": 0, "dead_lettered": 0}
        self.denied = 0

    def record(self, job: Job, *, denied: bool = False) -> None:
        with self._lock:
            self.counts["processed"] += 1
            self.counts[self._OUTCOMES.get(job.status, "retried")] += 1
            if denied:
                self.denied += 1

    def prometheus(self) -> str:
        with self._lock:
            lines = [
                f"governed_autonomy_worker_jobs_{name}_total {value}"
                for name, value in self.counts.items()
            ]
            lines.append(f"governed_autonomy_worker_jobs_denied_total {self.denied}")
        return "\n".join(lines) + "\n"


class WorkerRuntime:
    def __init__(
        self,
        store: JobStore,
        *,
        authorizer: Callable[[dict[str, Any]], dict[str, Any]],
        secrets: SecretProvider,
        sandbox: ContainerSandbox,
        timeout_seconds: float = 30.0,
        retry_delay: float = 1.0,
    ) -> None:
        self.store, self.authorizer, self.secrets = store, authorizer, secrets
        self.sandbox, self.timeout_seconds, self.retry_delay = sandbox, timeout_seconds, retry_delay
        self.last_output: str = ""
        self.metrics = WorkerMetrics()
        self._denied = False

    def process_once(self) -> Job | None:
        self._denied = False
        job = run_once(self.store, self._handle, retry_delay=self.retry_delay)
        if job is not None:
            self.metrics.record(job, denied=self._denied)
        return job

    def _handle(self, payload: dict[str, Any]) -> None:
        try:
            spec = self.authorizer(payload)
        except Exception as exc:
            self._denied = True
            raise RuntimeError("job not authorized") from exc
        if not isinstance(spec, dict):
            self._denied = True
            raise RuntimeError("job not authorized")
        payload = spec
        image, command = payload.get("image"), payload.get("command")
        if not isinstance(image, str) or not isinstance(command, list):
            raise ValueError("job requires image and command")
        required = payload.get("required_secrets", [])
        policy_id = payload.get("policy_id")
        secrets: dict[str, str] = {}
        if required:
            if not isinstance(policy_id, str):
                raise ValueError("policy_id is required when secrets are requested")
            secrets = self.secrets.fetch(policy_id, required)
        result = self.sandbox.execute(image, command, secrets, self.timeout_seconds)
        self.last_output = result.output
        if not result.ok:
            raise RuntimeError(f"execution failed with exit code {result.exit_code}")
