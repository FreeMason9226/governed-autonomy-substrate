"""Small standard-library load and availability smoke test for a deployed API."""
from __future__ import annotations

import os
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

URL = os.environ.get("GAS_URL", "http://127.0.0.1:8000")
TOKEN = os.environ["GAS_TOKEN"]
REQUESTS = int(os.environ.get("GAS_REQUESTS", "100"))
WORKERS = int(os.environ.get("GAS_WORKERS", "10"))


def check(_: int) -> float:
    started = time.perf_counter()
    request = urllib.request.Request(
        f"{URL}/readyz", headers={"Authorization": f"Bearer {TOKEN}"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"readiness returned {response.status}")
    return time.perf_counter() - started


def main() -> None:
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        durations = list(pool.map(check, range(REQUESTS)))
    durations.sort()
    p95 = durations[int(len(durations) * 0.95) - 1]
    print(f"requests={len(durations)} workers={WORKERS} p95_seconds={p95:.3f}")
    if p95 > float(os.environ.get("GAS_P95_LIMIT", "1.0")):
        raise SystemExit("p95 latency threshold exceeded")


if __name__ == "__main__":
    main()
