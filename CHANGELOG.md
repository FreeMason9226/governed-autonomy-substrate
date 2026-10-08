# Changelog

All notable changes are documented here. This project follows
[Semantic Versioning](https://semver.org/) for implementation releases and
maintains a separate **GAS Protocol Version** for wire-format changes.

## [Unreleased]

- Added an AWS KMS runtime signer configuration using the AWS credential chain and Helm service-account workload identity; the KMS deployment path does not inject raw issuer private keys.
- Pull requests now build and scan the package/container, audit installed project dependencies, and check source and container vulnerabilities. Added a 75% overall coverage floor.
- Aligned the OPA pull-request risk policy with the Python/deployment layout and added a CI check to detect drift in mirrored workflow sources.
- Added security reporting, ownership, dependency update, and issue-template metadata. Clarified that this repository currently provides a Python service rather than Substrate runtime pallets.

- Added single-tenant Microsoft Entra ID API authentication using OIDC discovery, rotating JWKS validation, exact issuer/audience/tenant checks, and API-only federated authentication (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`); Helm accepts `oidc.tenantId` and `oidc.clientId`.

- OIDC discovery now exposes validated authorization/token endpoints, JWKS URI, and advertised signing algorithms; discovery-based validators intersect provider algorithms with their configured allow-list.

- JWKS retrieval now uses bounded HTTPS responses, thread-safe cache refresh, detached cache results, public-key-only validation, and key-material rotation detection; expired caches fail closed when refresh is unavailable.

- Added `RuntimeIdentity.from_external_identity()` to normalize verified OIDC subject, tenant, name, email, roles, and groups; authenticated API authorization requests bind this context server-side and use it for operator-role checks and audit attribution.

- Added Microsoft Entra browser sign-in with Authorization Code + PKCE, one-time state/nonce validation, discovered endpoint code exchange, HttpOnly session cookies, same-origin logout/POST protection, and configurable Helm redirect URI/client secret.

- API versioning: `/api/v1/{health,livez,readyz,startupz,audit,openapi.json}` aliases and an `X-API-Version` response header.

- Structured JSON logging (`GOVERNED_AUTONOMY_LOG_LEVEL`, `GOVERNED_AUTONOMY_LOG_FORMAT`) with per-request access log; OpenAPI now documents response and error schemas.

- Added `docs/install-and-upgrade.md` (installation and upgrade procedures).

- Cluster CI now verifies a signed job through the Postgres queue and executes it in a real hardened Docker sandbox; replay is rejected afterwards. Added the `demo-jobs-v1` policy and documented that the Helm worker does not receive a host container socket. Fixed chart bugs found during cluster testing: the API Service selected worker pods, worker Postgres egress used a mismatched label, and `/admin` needed an optional `operator-token` secret key.

- Helm chart now verified on a real kind cluster in CI (cluster.yml). The test found and fixed a NetworkPolicy that blocked Postgres egress; added startup probe and longer probe timeouts.

- Add API-enforced enterprise RBAC for `platform_admin`, `policy_admin`, `operator`, `auditor`, and `approver`; governed action authorization/execution, policy lifecycle, approvals, jobs, audit reads, trust keys, and operator-key administration have separate role gates. Entra role values are case-insensitive; bootstrap operator tokens remain break-glass credentials and issued operator keys have only the Operator role.

### Added
- Opt-in CORS (`--cors-origins` / `GOVERNED_AUTONOMY_CORS_ORIGINS`, exact-origin allow-list, `OPTIONS` preflight); pipeline demo gained a *real server* mode.
- `render.yaml` blueprint and README button for a one-click public sandbox of the real server.
- Helm: worker metrics port, headless Service, optional ServiceMonitor and scrape-only NetworkPolicy ingress (`worker.metrics.*`).
- `docs/demo/pipeline.html`: interactive 8-stage governed request pipeline demo (policy evaluation, illustrative risk score, decision, execution, signed proof, hash-chained audit trail).
- Documentation: end-to-end deployment walkthrough, security model, benchmark report, and README architecture diagrams (Mermaid).
- `benchmarks/bench.py` reproducible benchmark harness with JSON output.
- Browser protocol demo (`docs/demo`, published via GitHub Pages workflow) and a Dev Container for Codespaces running the real server.
- gas job submit <gaa.json> and gas job status <job_id> enqueue and inspect worker jobs through the admin API.

- Roadmap platform slice: `AwsKmsBackend` (Ed25519 KMS signing for `KMSSigner`), `KeyLifecycleManager`, `WorkerRuntime`/`ContainerSandbox`/`VaultSecretProvider` (authorizer-gated, hardened sandbox, fail-closed secrets), `gas` operator CLI, worker Helm manifests, KMS IAM / Vault policy templates

- Wired the admin job API to the shared PostgreSQL queue when `DATABASE_URL` is configured, added operator-only job status lookup, and covered API submission through signed worker execution in PostgreSQL integration tests.

- `SPEC.md` — language-agnostic GAS Protocol Specification v1.0
- `tests/conformance/` — language-agnostic conformance test vector suite
- `CONTRIBUTING.md` — RFC process and contributor guide
- GitHub Actions CI across Python 3.11, 3.12, 3.13
- `.gitignore` — excludes runtime artifacts (`replay.jsonl`, `*.gas.db`, keys)

---

## [0.1.0] — 2026-09-21

### GAS Protocol Version: 1.0 (initial)

First working slice of the governance authorization and execution barrier.

### Added

- `GovernanceAuthorizationArtifact` (GAA) — Ed25519-signed, canonical-JSON-bound
  authorization artifact linking action request, policy decision, expiry, nonce,
  and replay frame reference
- `ReplayLog` / `SQLiteReplayLog` — append-only, hash-chained frame store with
  at-most-once nonce semantics and full chain verification on load
- `ExecutionBoundary` — verifies issuer signature, expiry, nonce uniqueness,
  frame reference, payload equality, allow decision, and action constraint before
  atomically claiming the nonce and invoking the action callable
- `DeterministicArbiter` — stateless policy evaluator with canonical policy
  digest, machine-readable denial reason codes, and approval quorum support
- `Policy` / `PolicyRegistry` / `SignedPolicyManifest` — versioned, signed
  policy definitions with registry persistence and rollback protection
- `SignedApproval` — detached multi-party approval evidence with request/decision
  binding
- `TrustStore` — issuer public-key registry with revocation and atomic
  persistence
- `GovernancePlatform` / `RuntimeIdentity` — deployable platform shell binding
  service identity, tenant, environment, and actor to requests
- `ServicePrincipal` / `ServicePrincipalRegistry` — tenant-scoped identity and
  access boundary with action/source/environment allowlists
- `PolicyChangeManager` — proposal/approval/activation workflow for safe policy
  rollouts
- `GovernanceRuleTranslator` — natural-language governance rule compiler
- `AuthorizationIssuer` — end-to-end workflow: arbitrate, append frame, issue
  signed GAA; supports compensation authorization for failed executions
- `GovernedService` — named-action dispatcher with `PolicyRegistry` integration
  and deterministic `audit_report()`
- `AuthenticatedAPI` / `create_server` — stdlib HTTP boundary with bearer auth,
  body limits, security headers, TLS wrapping, rate limiting, `/api/v1`
  versioned endpoints, `/openapi.json`, and health probes
- `SQLiteJobStore` — durable job state with idempotency, bounded retries,
  dead-letter, and compensation hooks
- `OIDCValidator`, `LocalEd25519Signer`, `RemoteSigner`,
  `SQLiteNonceRepository`, `PostgresNonceRepository` — production integration
  boundary adapters
- `health_report` — structured readiness check for replay integrity and
  configured trust/policy components
- `build_demo_service` — wires a complete issuer + trust + policy + boundary +
  replay + handler for integration demonstrations
- Prometheus text and OpenTelemetry-compatible observability hooks
- `Dockerfile`, `compose.yaml`, `deploy/kubernetes.yaml`, `deploy/helm/`,
  `docs/operations.md` — deployment and recovery starting points

- Added `POST /admin/jobs` (enable with `--job-store` / `GOVERNED_AUTONOMY_JOB_STORE`) to enqueue signed GAAs for the worker; emits a `job.submitted` governance event.
