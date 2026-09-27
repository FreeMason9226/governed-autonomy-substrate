# Platform compose example

Run the full platform stack with PostgreSQL-backed control-plane state:

```bash
docker compose -f examples/platform-compose/compose.yaml up --build
```

The stack starts:
- a PostgreSQL control plane database
- a migration job (`gas migrate`)
- the FastAPI service on `http://localhost:8000/v1`
- a polling worker (`python -m governed_autonomy.worker` via `gas-worker`)

Example authorize request:

```bash
curl -H "Authorization: ******" \\
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: demo-1' \
  http://localhost:8000/v1/authorize \
  -d '{"policy_id":"demo-files-v1","request":{"action":"write_file","path":"out.txt","content":"hello"}}'
```
