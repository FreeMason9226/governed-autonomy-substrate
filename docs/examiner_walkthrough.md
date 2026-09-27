# Examiner Walkthrough

Run from the repository root in a clean Python 3.11+ environment:

```powershell
python -m pip install -e '.[dev]'
$env:PYTHONPATH='src'
python examples/governance_bottleneck_demo.py
```

Expected output includes:

```text
without GAA: denied (execution requires a Governance Authorization Artifact)
with GAA: success
replay chain valid: True
```

Then independently verify the published compact record:

```powershell
python scripts/split_anchor_vector.py
python tools/verify-replay/verify_replay.py `
  --record evidence/anchor-sample/record.json `
  --frame evidence/anchor-sample/frame.json `
  --selection evidence/anchor-sample/selection.json
```

Expected output ends with `replay verification: OK`. Run the complete deterministic suite
with `python -m pytest`; the CI gate runs the same suite plus explicit security and
provenance checks.
