# verify-replay Demo

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

For an isolated run, build `tools/verify-replay/Dockerfile` and pass the same three JSON
files mounted under `/app/evidence/anchor-sample`.