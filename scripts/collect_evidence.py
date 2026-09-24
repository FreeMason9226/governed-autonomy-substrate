"""Collect local test, anchoring, and provenance evidence for review packages."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "evidence"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    OUT.mkdir(exist_ok=True)
    command = [
        "python",
        "-m",
        "pytest",
        "tests/test_governance_bottleneck_e2e.py",
        "tests/test_governance_service.py",
        "tests/test_kms_signing.py",
        "tests/test_registry_acl.py",
        "tests/test_anchoring_claim51a.py",
        "tests/test_gir_inference.py",
        "tests/test_resilience_observability.py",
        "-q",
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    (OUT / "focused-test-output.log").write_text(result.stdout + result.stderr, encoding="utf-8")
    vector_result = subprocess.run(
        ["python", "scripts/verify_anchor.py"], cwd=ROOT, capture_output=True, text=True, check=False
    )
    (OUT / "anchoring-verification.log").write_text(
        vector_result.stdout + vector_result.stderr, encoding="utf-8"
    )
    manifest = {
        "test_exit_code": result.returncode,
        "anchoring_exit_code": vector_result.returncode,
        "artifacts": {
            "dataset_manifest": sha256(ROOT / "training/dataset_manifest.json"),
            "inference_regression": sha256(ROOT / "training/inference_regression.jsonl"),
            "cryptographic_vectors": sha256(ROOT / "docs/cryptographic_vectors.json"),
            "checkpoint_manifest": sha256(ROOT / "training/checkpoints/checkpoint_manifest.json"),
        },
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    raise SystemExit(max(result.returncode, vector_result.returncode))


if __name__ == "__main__":
    main()