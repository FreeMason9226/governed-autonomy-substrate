# verify-replay

Independent compact-record verifier. It accepts an off-chain frame, an on-chain compact
record containing the CID and arbiter-selection digest, and the selection proof.

```powershell
$env:PYTHONPATH='src'
python scripts/split_anchor_vector.py
python tools/verify-replay/verify_replay.py `
  --record evidence/anchor-sample/record.json `
  --frame evidence/anchor-sample/frame.json `
  --selection evidence/anchor-sample/selection.json
```

Expected output:

```text
frame hash: verified
on-chain CID: verified
arbiter selection proof: verified
replay verification: OK
```
