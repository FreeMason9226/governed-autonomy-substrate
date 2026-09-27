"""Run reproducibility checks and generate local evidence reports and receipts."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(label: str, command: list[str]) -> dict[str, object]:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    (EVIDENCE / f"repro-{label}.log").write_text(output, encoding="utf-8")
    return {"label": label, "command": command, "exit_code": result.returncode}


def pdf(path: Path, title: str, lines: list[str]) -> None:
    content_lines = [title, ""] + lines
    commands = ["BT", "/F1 10 Tf", "50 760 Td"]
    for index, line in enumerate(content_lines):
        safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if index:
            commands.append("0 -14 Td")
        commands.append(f"({safe[:130]}) Tj")
    commands.append("ET")
    stream = "\n".join(commands).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    output.extend(b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:]))
    output.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    path.write_bytes(output)


def main() -> None:
    EVIDENCE.mkdir(exist_ok=True)
    (ROOT / "security").mkdir(exist_ok=True)
    (EVIDENCE / "anchor-sample").mkdir(exist_ok=True)
    subprocess.run([sys.executable, "scripts/split_anchor_vector.py"], cwd=ROOT, check=True)
    checks = [
        run("full-tests", [sys.executable, "-m", "pytest"]),
        run("demo", [sys.executable, "examples/governance_bottleneck_demo.py"]),
        run("anchor", [sys.executable, "scripts/verify_anchor.py"]),
        run(
            "verify-replay",
            [
                sys.executable,
                "tools/verify-replay/verify_replay.py",
                "--record",
                "evidence/anchor-sample/record.json",
                "--frame",
                "evidence/anchor-sample/frame.json",
                "--selection",
                "evidence/anchor-sample/selection.json",
            ],
        ),
        run("gir-smoke", [sys.executable, "-m", "pytest", "tests/test_gir_inference.py", "tests/test_gir_provenance.py"]),
    ]
    artifact_paths = [
        "gir/train/checkpoint_smoke.json",
        "gir/train/checkpoint_manifest.json",
        "replay/tests/anchoring_vectors.json",
        "docs/CANONICAL_SERIALIZATION.md",
        "training/dataset_manifest.json",
        "PATENT_SUPPORT.md",
        "COUNSEL_MEMO.md",
    ]
    hashes = {path: digest(ROOT / path) for path in artifact_paths}
    generated_at = datetime.now(timezone.utc).isoformat()
    report = {
        "generated_at": generated_at,
        "environment": {"python": sys.version, "platform": platform.platform(), "cwd": str(ROOT)},
        "seeds": {"gir": 20260923, "simulation": 20260923},
        "dependency_lock": digest(ROOT / "poetry.lock") if (ROOT / "poetry.lock").exists() else None,
        "checkpoint_hashes": hashes,
        "checks": checks,
        "limitations": [
            "Transformer weights are not vendored; the checkpoint hash covers deterministic smoke metadata.",
            "External KMS/HSM attestation and trusted timestamp notarization require provider credentials.",
        ],
    }
    (EVIDENCE / "reproducibility_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [
        f"Generated: {generated_at}",
        f"Python: {sys.version.split()[0]}",
        "Seeds: GIR=20260923; simulation=20260923",
        "Checks: " + ", ".join(f"{item['label']}={item['exit_code']}" for item in checks),
        "Dependency lock SHA-256: " + str(report["dependency_lock"]),
        "Checkpoint and artifact hashes:",
    ] + [f"{name}: {value}" for name, value in hashes.items()] + [
        "Status: local reproducibility evidence; external KMS and trusted timestamp receipts pending.",
    ]
    pdf(EVIDENCE / "reproducibility_report.pdf", "GAS Reproducibility Report", lines)
    pdf(ROOT / "security" / "key_attestation.pdf", "KMS/HSM Key-Control Attestation Status", [
        "STATUS: PENDING EXTERNAL PROVIDER ATTESTATION",
        "The production adapter requires a remote KMS/HSM signer and exposes no private key material.",
        "This document is a status record, not a third-party attestation or certification.",
    ])
    pdf(EVIDENCE / "patent_memo.pdf", "Patent Evidence Memo", [
        "See COUNSEL_MEMO.md for the complete technical mapping.",
        "GAA bottleneck: issuer.py, engine.py, tests/test_governance_bottleneck_e2e.py.",
        "GIR: training/, gir/train/, tests/test_gir_inference.py.",
        "Claim 51A: claim51a.py, tests/test_anchoring_claim51a.py.",
        "Anchoring: anchoring.py, verify_replay.py, replay/tests/anchoring_vectors.json.",
        "External legal, KMS, timestamp, and security-review conclusions remain pending.",
    ])
    timestamps = {
        "generated_at": generated_at,
        "method": "local-sha256-receipt",
        "trusted_timestamp_service": None,
        "receipts": [
            {"artifact": name, "sha256": value, "anchor_txid": None, "status": "local receipt"}
            for name, value in hashes.items()
        ],
    }
    (EVIDENCE / "timestamps.json").write_text(json.dumps(timestamps, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    bundle = EVIDENCE / "patent_bundle.zip"
    include = [
        "PATENT_SUPPORT.md", "COUNSEL_MEMO.md", "RELEASE_NOTES.md", "RELEASE_CHECKLIST.md",
        "evidence/reproducibility_report.json", "evidence/reproducibility_report.pdf",
        "evidence/patent_memo.pdf", "evidence/timestamps.json", "tools/browser_context.json",
        "security/key_attestation.pdf",
        "docs/CANONICAL_SERIALIZATION.md", "replay/tests/anchoring_vectors.json",
        "training/dataset_manifest.json", "training/checkpoints/checkpoint_manifest.json",
        "gir/train/dataset_manifest.json", "evidence/repro-full-tests.log", "evidence/repro-demo.log",
        "evidence/repro-anchor.log", "evidence/repro-verify-replay.log", "evidence/repro-gir-smoke.log",
        "performance/load_test_report.md", "performance/load_test_result.json",
    ]
    with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in include:
            path = ROOT / item
            if path.exists():
                archive.write(path, path.relative_to(ROOT).as_posix())
    print(f"created {EVIDENCE / 'reproducibility_report.pdf'}")
    print(f"created {bundle}")


if __name__ == "__main__":
    main()