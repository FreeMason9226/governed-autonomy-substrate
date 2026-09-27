"""Small deterministic arbitration throughput baseline."""

from __future__ import annotations

import time

from governed_autonomy import DeterministicArbiter, Policy


def run(iterations: int = 10000) -> dict[str, float | int]:
    policy = Policy("load-v1", ("read",), {"read": ("resource",)}, {})
    request = {"action": "read", "resource": "item"}
    arbiter = DeterministicArbiter()
    start = time.perf_counter()
    for _ in range(iterations):
        assert arbiter.decide(request, policy)["allow"]
    elapsed = time.perf_counter() - start
    return {"iterations": iterations, "elapsed_seconds": elapsed, "decisions_per_second": iterations / elapsed}


if __name__ == "__main__":
    print(run())