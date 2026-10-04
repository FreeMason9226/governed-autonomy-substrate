"""Reproducible micro- and end-to-end benchmarks for the governance barrier.

Run from the repo root::

    python benchmarks/bench.py                 # markdown tables
    python benchmarks/bench.py --json out.json # also write machine-readable results

Every measurement uses the real code paths (Ed25519 signing, hash-chained replay
frames, nonce claim, policy re-evaluation). Numbers depend on the host; the
environment block in the output records what produced them.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPConnection
from pathlib import Path

from governed_autonomy import KeyPair, build_demo_service, create_server
from governed_autonomy.crypto import verify_signature
from governed_autonomy.engine import ExecutionBoundary
from governed_autonomy.issuer import AuthorizationIssuer
from governed_autonomy.policy import Policy, PolicyRegistry
from governed_autonomy.replay import SQLiteReplayLog
from governed_autonomy.service import GovernedService
from governed_autonomy.trust import TrustStore

POLICY = "demo-files-v1"
REQUEST = {"action": "write_file", "path": "out.txt", "content": "benchmark"}


def percentile(ordered: list[float], fraction: float) -> float:
    return ordered[min(len(ordered) - 1, round(fraction * (len(ordered) - 1)))]


def summarize(name: str, samples: list[float], total_seconds: float) -> dict:
    ordered = sorted(samples)
    return {
        "name": name,
        "iterations": len(samples),
        "ops_per_sec": round(len(samples) / total_seconds, 1),
        "mean_us": round(statistics.fmean(samples) * 1e6, 1),
        "p50_us": round(percentile(ordered, 0.50) * 1e6, 1),
        "p95_us": round(percentile(ordered, 0.95) * 1e6, 1),
        "p99_us": round(percentile(ordered, 0.99) * 1e6, 1),
    }


def timed(name: str, iterations: int, fn) -> dict:
    for _ in range(min(50, iterations)):
        fn()
    samples = []
    started = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return summarize(name, samples, time.perf_counter() - started)


def sqlite_service(path: str) -> GovernedService:
    base, issuer, _ = build_demo_service()
    log = SQLiteReplayLog(path)
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    policies = PolicyRegistry(
        (
            Policy(
                POLICY,
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            ),
        )
    )
    return GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=log),
        boundary=ExecutionBoundary(replay_log=log, trust_store=trust, policy_registry=policies),
        policies=policies,
        actions=base.actions,
    )


def authorize_execute(service: GovernedService) -> None:
    service.execute(service.authorize(REQUEST, POLICY))


def bench_in_process(iterations: int) -> list[dict]:
    results = []
    key = KeyPair.generate("bench")
    message = b"x" * 512
    signature = key.sign(message)
    results.append(timed("Ed25519 sign (512 B)", iterations * 4, lambda: key.sign(message)))
    results.append(
        timed(
            "Ed25519 verify (512 B)",
            iterations * 4,
            lambda: verify_signature(key.public_key, message, signature),
        )
    )

    service, _, _ = build_demo_service()
    results.append(
        timed("authorize (in-memory log)", iterations, lambda: service.authorize(REQUEST, POLICY))
    )
    service, _, _ = build_demo_service()
    results.append(
        timed(
            "authorize + execute (in-memory log)",
            iterations,
            lambda: authorize_execute(service),
        )
    )

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        durable = sqlite_service(str(Path(tmp) / "bench.sqlite"))
        results.append(
            timed(
                "authorize + execute (SQLite log)",
                max(200, iterations // 4),
                lambda: authorize_execute(durable),
            )
        )

    service, _, _ = build_demo_service()
    artifact = service.authorize(REQUEST, POLICY)
    service.execute(artifact)

    def replay_attempt() -> None:
        try:
            service.execute(artifact)
        except Exception:  # noqa: BLE001 - the denial is the measured behavior
            return
        raise SystemExit("replayed artifact was accepted")

    results.append(timed("replayed artifact rejected", iterations, replay_attempt))

    service, _, log = build_demo_service()
    for _ in range(1000):
        authorize_execute(service)
    started = time.perf_counter()
    assert log.verify_integrity()["ok"]
    elapsed = time.perf_counter() - started
    frames = len(log.frames)
    results.append(
        {
            "name": f"verify {frames:,}-frame hash chain",
            "iterations": 1,
            "ops_per_sec": round(frames / elapsed, 1),
            "mean_us": round(elapsed * 1e6, 1),
            "p50_us": None,
            "p95_us": None,
            "p99_us": None,
            "unit": "frames/sec",
        }
    )
    return results


def bench_http(requests_per_level: int, levels: tuple[int, ...]) -> list[dict]:
    results = []
    for concurrency in levels:
        service, _, _ = build_demo_service()
        server = create_server(service, bearer_token="bench-token", rate_limit=10_000_000)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        authorize_body = json.dumps({"policy_id": POLICY, "request": REQUEST}).encode()

        def call(conn: HTTPConnection, path: str, payload: bytes) -> bytes:
            conn.request(
                "POST",
                path,
                body=payload,
                headers={
                    "Authorization": "Bearer bench-token",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(payload)),
                },
            )
            response = conn.getresponse()
            data = response.read()
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}: {data[:120]!r}")
            return data

        def worker(count: int, host=host, port=port, authorize_body=authorize_body) -> list[float]:
            conn = HTTPConnection(host, port)
            samples = []
            for _ in range(count):
                t0 = time.perf_counter()
                artifact = json.loads(call(conn, "/authorize", authorize_body))
                call(conn, "/execute", json.dumps({"artifact": artifact}).encode())
                samples.append(time.perf_counter() - t0)
            conn.close()
            return samples

        worker(20)
        per_worker = max(1, requests_per_level // concurrency)
        started = time.perf_counter()
        with ThreadPoolExecutor(concurrency) as pool:
            batches = list(pool.map(worker, [per_worker] * concurrency))
        elapsed = time.perf_counter() - started
        samples = [value for batch in batches for value in batch]
        results.append(
            summarize(f"authorize + execute over HTTP, {concurrency} client(s)", samples, elapsed)
        )
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    return results


def environment() -> dict:
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
    }


def render(title: str, rows: list[dict]) -> str:
    def cell(row: dict, key: str) -> str:
        value = row.get(key)
        return "-" if value is None else f"{value:,.0f} µs"

    lines = [
        f"### {title}",
        "",
        "| Benchmark | Iterations | Throughput | Mean | p50 | p95 | p99 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row['name']} | {row['iterations']:,} "
            f"| {row['ops_per_sec']:,.0f} {row.get('unit', 'ops/s')} "
            f"| {cell(row, 'mean_us')} | {cell(row, 'p50_us')} "
            f"| {cell(row, 'p95_us')} | {cell(row, 'p99_us')} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--http-requests", type=int, default=800)
    parser.add_argument("--json", help="write machine-readable results to this path")
    args = parser.parse_args()

    in_process = bench_in_process(args.iterations)
    http = bench_http(args.http_requests, (1, 4, 16))
    env = environment()
    print("### Environment\n")
    for key, value in env.items():
        print(f"- {key}: {value}")
    print()
    print(render("In-process barrier", in_process))
    print()
    print(render("HTTP API (one authorize + one execute per iteration)", http))
    if args.json:
        Path(args.json).write_text(
            json.dumps({"environment": env, "in_process": in_process, "http": http}, indent=2),
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
