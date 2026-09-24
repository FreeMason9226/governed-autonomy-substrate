# Independent Replay Verification

Run from the repository root:

```powershell
python scripts/split_anchor_vector.py
python -m governed_autonomy.verify_replay `
  --record evidence/anchor-sample/record.json `
  --frame evidence/anchor-sample/frame.json `
  --selection evidence/anchor-sample/selection.json
```

The CLI accepts separate JSON files in production. The sample vector is a combined
fixture; use `scripts/split_anchor_vector.py` to create the three files for the command.
Expected output includes:

```text
frame hash: verified
on-chain CID: verified
arbiter selection proof: verified
replay verification: OK
```