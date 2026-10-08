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
| `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID` | Single-tenant Microsoft Entra ID API-token validation; discovery and JWKS are resolved automatically |
| `ENTRA_REDIRECT_URI`, `ENTRA_CLIENT_SECRET` | Enable server-side Entra authorization-code sign-in (secret optional for a PKCE public client) |
| `DATABASE_URL` | PostgreSQL for replay log and job queue |
| `GAS_IDENTITY_STORE` | Optional SQLite identity database for local/single-node user, service-principal, role-assignment, and identity-event storage; `DATABASE_URL` selects PostgreSQL instead |

Run `gas-server --help` for the full flag list. Invalid configuration fails
at startup, before the listener binds.

### AWS KMS signing

The AWS KMS signer can be selected with `GAS_ISSUER_SIGNER=aws-kms` and
`GAS_ISSUER_KMS_KEY_ID=<key-id-or-arn>`. The runtime uses the AWS SDK default
credential chain, so Kubernetes deployments should use workload identity (for
example, EKS IRSA) rather than static AWS credentials. Install the `aws` extra;
the provided container image includes it.

For Helm, enable `kms.enabled`, set `kms.keyId`, and configure a service account
using `serviceAccount.create` and `serviceAccount.annotations` for the cluster's
workload-identity binding. Set `kms.region` when it cannot be inferred from the
runtime environment. The chart mounts the service-account token only when KMS is
enabled and omits the raw issuer-private-key environment variable in that mode.
The configured AWS role must be scoped to the selected KMS key and signing
operations. API and worker currently share this service account; separate
least-privilege identities are a remaining hardening item. KMS mode does not
provision keys or IAM permissions.

### Microsoft Entra ID

Register GAS as an API in the Entra admin center, expose an application ID URI,
and configure the client application to request an access token for that API.
Set `ENTRA_TENANT_ID` to the tenant GUID and `ENTRA_CLIENT_ID` to the GAS API
application's client ID (the expected access-token audience). GAS discovers
that tenant's v2.0 issuer and signing keys over HTTPS, verifies the token
signature, issuer, audience, expiry and `tid` tenant claim, and uses the
validated subject for audit attribution. The tenant and client IDs must be
GUIDs; generic `OIDC_*` settings cannot be combined with Entra settings.
For Helm, set `oidc.enabled=true`, `oidc.tenantId`, and `oidc.clientId`; leave
the generic `oidc.issuer`, `oidc.audience`, and `oidc.jwksUrl` unset.

To enable browser sign-in, register a **Web** redirect URI such as
`https://gas.example.com/auth/callback` on the same Entra app registration,
then set `ENTRA_REDIRECT_URI` to that exact value. Start sign-in by navigating
to `/auth/login` (optionally `?next=%2Fadmin`); an unauthenticated browser
visiting `/admin` is also redirected to sign-in. GAS redirects to the tenant's
discovered authorization endpoint with Authorization Code flow, `state`,
`nonce`, and PKCE S256, exchanges the code at the discovered token endpoint,
and validates the ID token signature, issuer, audience, expiry, tenant, and
nonce before creating a browser session. `ENTRA_CLIENT_SECRET` may be supplied
for a confidential web client. The HttpOnly, SameSite=Lax session cookie is
Secure by default; `OIDC_COOKIE_INSECURE=true` is only for local HTTP
development. `POST /auth/logout` revokes the local session and requires a
same-origin `Origin` header.

Browser sessions are held in process memory and expire at the earlier of the
ID token expiry or eight hours; a server restart logs users out. The Helm chart
sets one API replica when `oidc.redirectUri` enables browser sessions so the
in-memory state/session store is not split between pods. Multi-replica browser
sessions require a shared session-store implementation.

### Device-code CLI and identity administration

Install the Entra client dependencies and sign in without embedding a shared
operator token in the application:

```powershell
pip install ".[entra]"
gas auth login --api-url https://gas.example.com `
  --tenant-id <tenant-guid> --client-id <api-app-guid>
```

The CLI requests `api://<api-app-guid>/access_as_user` unless `--scopes` is
provided. MSAL uses an OS-protected persistent token cache (DPAPI on Windows,
Keychain on macOS, or the configured Linux secret-store backend); the CLI's
credentials JSON contains only tenant, client, scope, and API URL metadata.
Protect the user's account and OS profile as usual. A bootstrap `--token`
override remains available for controlled local recovery only.

For durable identity records and role assignments, PostgreSQL deployments
should apply `deploy/postgres/migrations/002_identity_schema.sql` using the
deployment's migration process and configure `DATABASE_URL`. Single-node
development may use `GAS_IDENTITY_STORE` with a SQLite file. The API exposes
`GET /auth/me`, read endpoints under `/admin/identities/`, and a
`platform_admin`-only `POST /admin/identities/role-assignments` accepting
`{"principal_id":"...","role":"operator"}`. Claims-based roles and explicit
assignments are combined; unknown roles fail closed. OIDC identity data is
bound into every authorization request before the signed GAA is issued.

One-time JWT replay protection is exposed by `JWTValidator.validate_once()`
and supports an injected SQLite or PostgreSQL replay store. It requires a
signed `jti`. Normal OAuth bearer access tokens remain reusable across
requests; do not configure their validation as one-time.

In Entra mode static bearer tokens are not accepted for API requests. If
`GOVERNED_AUTONOMY_BEARER_TOKEN` is configured, it is restricted to the
authenticated health-probe routes (`/health`, `/livez`, `/readyz`, and
`/startupz`) so existing container probes can remain functional. The Helm
chart uses this token only for its health probes. Interactive
client applications may also send access tokens as bearer tokens; GAS validates
them independently of the browser-session flow. The Entra-only mode does not
accept the static operator token or operator API keys; grant administrative
access through mapped Entra roles/scopes.

Entra `roles` and `scope`/`scp` claims map to the platform roles
`PlatformAdmin`, `PolicyAdmin`, `Operator`, `Auditor`, and `Approver`
(role names are case-insensitive; underscores and hyphens are ignored).
`PlatformAdmin` is the superuser. `PolicyAdmin` can prepare, submit, and
activate policy proposals; `Approver` can prepare and submit approvals;
`Operator` can authorize/execute governed actions, submit jobs, and use
operational views; `Auditor` has read-only access to audit and administration
views. Only `PlatformAdmin` can modify trusted keys or manage operator API keys.
Configure these as Entra app roles
and assign them to users/groups in the enterprise application. For backward
compatibility outside Entra-only mode, the explicitly configured bootstrap
operator token remains a full-administration break-glass credential; issued
operator API keys are limited to the `Operator` role.
