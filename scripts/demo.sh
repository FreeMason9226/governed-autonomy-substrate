#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH="${PYTHONPATH:-src}"
python examples/governance_bottleneck_demo.py
python scripts/split_anchor_vector.py
python -m governed_autonomy.verify_replay \
  --record evidence/anchor-sample/record.json \
  --frame evidence/anchor-sample/frame.json \
  --selection evidence/anchor-sample/selection.json