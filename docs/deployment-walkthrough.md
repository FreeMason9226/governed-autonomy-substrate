# End-to-end deployment walkthrough

From a laptop to Kubernetes in six steps. Each step is verifiable before moving on.

| Step | Goal | Time |
|---|---|---|
| 1 | Run locally | 2 min |
| 2 | Authorize and execute with curl | 2 min |
| 3 | Operate with the `gas` CLI and admin UI | 3 min |
| 4 | Docker Compose | 3 min |
| 5 | Postgres + worker + job queue | 10 min |
| 6 | Kubernetes with Helm | 15 min |

## 1. Run locally

```bash
python -m pip install -e ".[postgres]"
gas-demo                    # runs a full authorize/execute cycle, writes replay.jsonl
gas replay verify replay.jsonl
export GOVERNED_AUTONOMY_BEARER_TOKEN=dev-token
export GOVERNED_AUTONOMY_OPERATOR_TOKEN=dev-operator
gas-server --port 8000
```

Check: `curl localhost:8000/livez` returns OK; open <http://localhost:8000/admin> for the operator UI.

## 2. Authorize and execute

```bash
H='Authorization: Bearer dev-token'
curl -s -H "$H" -H 'Content-Type: application/json' localhost:8000/authorize \
  -d '{"policy_id":"demo-files-v1","request":{"action":"write_file","path":"out.txt","content":"hello"}}' > gaa.json
curl -s -H "$H" -H 'Content-Type: application/json' localhost:8000/execute \
  -d "{\"artifact\": $(cat gaa.json)}"
# Run the execute call a second time: it is rejected (nonce already consumed).
curl -s -H "$H" localhost:8000/audit
```

The schema is at `/openapi.json`. Field names for requests depend on the policy; the demo policy requires `path` and `content`.

## 3. CLI and admin UI

```bash
gas auth login --api-url http://localhost:8000 --token dev-operator
gas auth status
gas operator-key create alice
gas job submit gaa.json          # enqueue for a worker (needs the job store, step 5)
gas job status <job-id>
```

The admin UI (`/admin`) manages policies, proposals, trust keys, operator keys and the governance log. Governance changes are signed in the browser.

## 4. Docker Compose

```bash
docker compose up --build -d
curl -H 'Authorization: Bearer local-development-token' localhost:8000/livez
```

`compose.yaml` runs memory mode on port 8000 with a development token. Change it before exposing the port.

## 5. Postgres, issuer key and worker

```bash
export DATABASE_URL=postgresql://gas:gas@localhost:5432/gas
export GAS_RUNTIME_MODE=postgres
export GAS_ISSUER_KEY_ID=issuer-1
export GAS_ISSUER_PRIVATE_KEY=<base64url Ed25519 seed>   # dev only; use KMS in production
gas-server --port 8000
```

Start the worker in another shell:

```bash
export GAS_WORKER_IMAGES=registry.example.com/my-action:1.0   # allow-listed sandbox images
export VAULT_ADDR=https://vault.example.com VAULT_TOKEN=...   # optional per-job secrets
export GAS_WORKER_METRICS_PORT=9100
gas-worker
```

The server's `POST /admin/jobs` (or `gas job submit`) enqueues a GAA; the worker claims it with `SKIP LOCKED` leases, re-verifies it through the barrier and runs the sandboxed container. Poll `gas job status`.

For KMS signing apply `deploy/security/aws-kms-iam-policy.json` to the service role; for Vault apply `deploy/security/vault-worker-policy.hcl`.

The Helm worker pod does not have a container runtime or access to a node container socket. The kind CI integration runs `gas-worker` on the runner's Docker host while it connects to the cluster's PostgreSQL queue; this verifies real sandbox execution without granting the pod host-level access. For production Kubernetes deployments, use a dedicated sandbox backend rather than mounting the node's container socket.

## 6. Kubernetes (Helm)

```bash
kubectl create namespace gas
kubectl -n gas create secret generic governed-autonomy --from-literal=bearer-token="$(openssl rand -hex 32)"
kubectl -n gas create secret generic governed-autonomy-runtime \
  --from-literal=database-url=postgresql://... \
  --from-literal=issuer-key-id=issuer-1 \
  --from-literal=issuer-private-key=...
helm upgrade --install gas deploy/helm -n gas \
  --set image.repository=ghcr.io/<owner>/governed-autonomy-substrate \
  --set image.tag=<release> \
  --set ingress.enabled=true --set ingress.host=gas.example.com \
  --set serviceMonitor.enabled=true --set prometheusRule.enabled=true
kubectl -n gas rollout status deploy/gas-governed-autonomy
```

Use `externalSecrets.enabled=true` to sync secrets from your store, `oidc.*` for OIDC, and `postgres.enabled=true` for the bundled database (use a managed one in production). For Microsoft Entra ID, set `oidc.enabled=true`, `oidc.tenantId=<tenant-guid>`, and `oidc.clientId=<api-app-guid>`; the chart resolves discovery and JWKS automatically. To enable browser sign-in, also set `oidc.redirectUri=https://gas.example.com/auth/callback` and provision secret key `entra-client-secret` (optional for PKCE public clients) in `runtimeSecret` or `oidc.clientSecretSecret`. With `DATABASE_URL`, browser OIDC state, sessions, and rate-limit windows use PostgreSQL, allowing the configured API replica count; apply migration `003_ha_sessions_rate_limit.sql` before rollout. The bearer-token secret is used only by Kubernetes health probes in Entra mode, not for API access. The worker is off by default; enable it in `values.yaml` once images and Vault are ready. Resource names depend on the release name; check with `kubectl -n gas get all`.

## Browser access (CORS)

CORS is off by default. To let a web page call the API, set `GOVERNED_AUTONOMY_CORS_ORIGINS` (or `--cors-origins`) to a comma-separated list of exact origins, e.g. `https://example.github.io`. Only those origins get `Access-Control-Allow-Origin`; preflights from others are refused, and bearer auth is still required on every call. Never put a real token in a public page.

## Verify and observe

- `/livez`, `/readyz`, `/startupz` for probes; `/health` for replay and trust integrity.
- `/admin/metrics` (Prometheus) feeds the ServiceMonitor and alerts in `deploy/observability/`.
- `gas replay verify <file>` checks an exported log offline.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Connection refused in a container | Server bound to 127.0.0.1; set `GOVERNED_AUTONOMY_HOST=0.0.0.0` (image default) |
| 401 | Wrong bearer/operator token |
| `/readyz` fails | Database unreachable or replay chain invalid (fails closed) |
| Execute denied | Expired, already consumed, revoked issuer, or policy changed since authorization |
| Jobs stay queued | Worker not running, or image not in `GAS_WORKER_IMAGES` |

See also: [security model](security-model.md), [benchmarks](benchmarks.md), [operations](operations.md).
