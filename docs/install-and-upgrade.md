# Installation and upgrade

## Install

- **Docker**: `docker build -t gas .` then
  `docker run -p 8000:8000 -e GOVERNED_AUTONOMY_BEARER_TOKEN=... gas`.
  The image runs as a non-root user and has a `/livez` health check.
- **Docker Compose**: `docker compose up` (see `compose.yaml`).
- **Kubernetes**: `helm upgrade --install gas deploy/helm -n gas -f values.yaml`.
  See `docs/deployment-walkthrough.md` for secrets, ingress and worker setup.

Configuration is via environment variables (`GOVERNED_AUTONOMY_*`, `DATABASE_URL`)
or Helm values. Probes: `/livez`, `/readyz`, `/startupz`. API: `/api/v1/*`;
the OpenAPI document is served at `/openapi.json`.

## Upgrade procedure

1. Read `CHANGELOG.md` for breaking changes and GAS Protocol Version changes.
2. Back up PostgreSQL (see `docs/operations.md`).
3. Run migrations first, reviewed, with `gas migrate` (the app does not
   auto-migrate at startup). Migrations are additive.
4. Upgrade: `helm upgrade gas deploy/helm -n gas --reuse-values --set image.tag=<new>`.
5. Verify: `kubectl -n gas rollout status deploy/gas-governed-autonomy`, then
   check `/readyz` and run `deploy/scripts/rollback-smoke.sh`.
6. Roll back with `helm rollback gas <revision> -n gas` if verification fails
   (restore the backup only if a migration must be reverted).

## Configuration reference

Flags override nothing implicitly; environment variables supply defaults.

| Variable | Purpose |
|---|---|
| `GOVERNED_AUTONOMY_BEARER_TOKEN` | Static bearer token (required unless OIDC is configured) |
| `GOVERNED_AUTONOMY_HOST` | Listen address (default `127.0.0.1`; image sets `0.0.0.0`) |
| `GOVERNED_AUTONOMY_CORS_ORIGINS` | Exact-origin CORS allow-list |
| `GOVERNED_AUTONOMY_LOG_LEVEL` | `DEBUG`..`CRITICAL` (default `INFO`) |
| `GOVERNED_AUTONOMY_LOG_FORMAT` | `json` (default) or `text` |
| `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_URL`, `OIDC_DISCOVERY` | Operator SSO |
| `DATABASE_URL` | PostgreSQL for replay log and job queue |

Run `gas-server --help` for the full flag list. Invalid configuration fails
at startup, before the listener binds.
