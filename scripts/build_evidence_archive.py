"""Build a single counsel evidence archive from reproducible local artifacts."""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = ROOT / "evidence" / "governed-autonomy-evidence.zip"


def main() -> None:
    subprocess.run(["python", "scripts/collect_evidence.py"], cwd=ROOT, check=True)
    subprocess.run(["python", "scripts/split_anchor_vector.py"], cwd=ROOT, check=True)
    subprocess.run(
        [
            "python",
            "-m",
            "governed_autonomy.verify_replay",
            "--record",
            "evidence/anchor-sample/record.json",
            "--frame",
            "evidence/anchor-sample/frame.json",
            "--selection",
            "evidence/anchor-sample/selection.json",
        ],
        cwd=ROOT,
        check=True,
    )
    include = [
        "evidence",
        "coverage.xml",
        "COUNSEL_MEMO.md",
        "PATENT_SUPPORT.md",
        "RELEASE_CHECKLIST.md",
        "RELEASE_NOTES.md",
        "RUNBOOK.md",
        "SECURITY_REVIEW_REQUEST.md",
        "docs/CANONICAL_SERIALIZATION.md",
        "docs/incident-runbook.md",
        "docs/cryptographic_vectors.json",
        "docs/reproducibility.md",
        "replay/tests/anchoring_vectors.json",
        "training/dataset_manifest.json",
        "training/inference_regression.jsonl",
        "training/checkpoints/checkpoint_manifest.json",
        "gir/train/dataset_manifest.json",
        "gir/train/checkpoint_manifest.json",
        "deploy/observability/gas-dashboard.json",
        ".github/workflows/ci.yml",
        "tools/browser_context.json",
        "tools/verify-replay/README.md",
        "tools/verify-replay/verify_replay.py",
    ]
    ARCHIVE.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(ARCHIVE, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for item in include:
            path = ROOT / item
            if path.is_dir():
                for child in path.rglob("*"):
                    if child.is_file() and child != ARCHIVE:
                        bundle.write(child, child.relative_to(ROOT).as_posix())
            elif path.is_file():
                bundle.write(path, path.relative_to(ROOT).as_posix())
    print(f"created {ARCHIVE}")


if __name__ == "__main__":
    main()