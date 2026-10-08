"""Small standard-library load and availability smoke test for a deployed API."""
from __future__ import annotations

import json
import os
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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


def certify_anchor() -> None:
    anchor_file = os.environ.get("GAS_REPLAY_ANCHOR_FILE")
    required = os.environ.get("GAS_REQUIRE_REPLAY_CERTIFICATION", "").lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not anchor_file:
        if required:
            raise SystemExit("GAS_REPLAY_ANCHOR_FILE is required for replay certification")
        return
    try:
        anchor = json.loads(Path(anchor_file).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("GAS_REPLAY_ANCHOR_FILE must contain an AuditAnchor JSON object") from exc
    if not isinstance(anchor, dict):
        raise SystemExit("GAS_REPLAY_ANCHOR_FILE must contain an AuditAnchor JSON object")
    request = urllib.request.Request(
        f"{URL.rstrip('/')}/audit/replay/certify",
        data=json.dumps(anchor).encode(),
        headers={
            "Authorization": " ".join(("Bearer", TOKEN)),
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        certification = json.loads(response.read())
    if certification.get("certified") is not True:
        raise SystemExit("replay anchor certification failed")
    print(
        "replay_certified=true "
        f"frame_count={certification['integrity']['frame_count']} "
        f"signer_key_id={certification['signer_key_id']}"
    )


def main() -> None:
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        durations = list(pool.map(check, range(REQUESTS)))
    durations.sort()
    p95 = durations[int(len(durations) * 0.95) - 1]
    print(f"requests={len(durations)} workers={WORKERS} p95_seconds={p95:.3f}")
    if p95 > float(os.environ.get("GAS_P95_LIMIT", "1.0")):
        raise SystemExit("p95 latency threshold exceeded")
    certify_anchor()


if __name__ == "__main__":
    main()
