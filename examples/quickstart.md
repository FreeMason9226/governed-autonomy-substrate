# Quickstart

```powershell
python -m pip install -e '.[dev]'
$env:PYTHONPATH='src'
python examples/governance_bottleneck_demo.py
python -m pytest tests/test_governance_bottleneck_e2e.py tests/test_verify_replay.py
```

The first command demonstrates denial without a GAA, successful governed execution, and
replay verification. The second command verifies the bottleneck and independent CID proof.