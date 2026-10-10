# Operations runbook

## Configuration

Never use the demo server with a default credential. Set
`GOVERNED_AUTONOMY_BEARER_TOKEN` from a secret manager, or integrate an
`OIDCValidator` with a provider-owned JWKS cache. TLS termination, ingress
authorization, key rotation, and network policy remain deployment controls.

## Migrations, backup, and disaster recovery

Apply `POSTGRES_NONCE_SCHEMA`, `POSTGRES_REPLAY_SCHEMA`, and
`deploy/postgres/migrations/003_ha_sessions_rate_limit.sql` through a reviewed,
versioned migration tool. Back up replay frames and policy/trust snapshots
with encryption and retention controls. Restore into an isolated environment,
verify the hash chain and signatures, then promote only after readiness checks.
Do not fabricate certificates, keys, or cloud credentials in this repository.
The initial PostgreSQL migration is also checked in at
`deploy/postgres/migrations/001_replay_schema.sql`; run it through the
organization's migration controller before enabling application traffic.

## Security response

Revoke compromised trust keys, stop authorization issuance, preserve the
append-only log, and investigate correlated request IDs. Failed executions
consume their nonce; use an explicitly authorized compensation job rather than
retrying an artifact.

## Deployment validation

Validate YAML and container policy in CI with the target cluster's tooling.
The included Docker Compose and Kubernetes manifests are safe starting
artifacts, not a provisioned cluster or production certificate configuration.

## CI/CD deployment contract

The GitHub Actions workflow builds wheels and containers, generates CycloneDX
SBOMs, runs dependency/source/container scans, performs a Compose smoke test,
publishes images to GHCR, and creates tagged GitHub Releases. The `develop`
branch deploys to the `development` Environment. A `vX.Y.Z` tag promotes the
image through the `staging` and `production` Environments.

Configure `KUBECONFIG_B64` as an environment secret in each deployment
environment. Provision the `governed-autonomy` Kubernetes Secret with the
`bearer-token` key before installing the chart, unless a controlled environment
explicitly enables `createBearerTokenSecret`. Production environments should
also configure approval rules, private-registry pull credentials when needed,
TLS at the ingress, external secret management, and a Prometheus Operator
before enabling `serviceMonitor`.

### Cluster and GitHub setup

Create three real Kubernetes contexts or clusters and configure GitHub
Environments named `development`, `staging`, and `production`. Each
Environment requires a `KUBECONFIG_B64` secret containing a short-lived,
namespace-scoped service-account kubeconfig. `production` should require
reviewers and restrict deployments to release tags. `GAS_URL` is an Environment
variable and `GAS_TOKEN` is an Environment secret for post-deploy verification.

Install cert-manager, External Secrets Operator, the Prometheus Operator, and
an ingress controller before enabling their chart values. The cluster must
provide a `ClusterSecretStore` named `gas-secrets`; the application chart does
not create cloud credentials or provider access policies.

The manual workflow [staging-operations.yml](../.github/workflows/staging-operations.yml)
requires staging variables `GAS_URL`, `CERT_EMAIL`, `LOG_FORWARD_HOST`,
`LOG_FORWARD_PORT`, and secrets `KUBECONFIG_B64`, `GAS_TOKEN`, and
`BACKUP_BEARER_TOKEN` when restore testing is enabled. Configure GitHub
Environment required reviewers on `staging` before using the workflow.

### Recovery drills

Run `deploy/scripts/rollback-smoke.sh` with an explicitly selected Helm
revision during each release exercise. Restore a recent dump in an isolated
PostgreSQL instance with `deploy/scripts/dr-restore-check.sh`, then run the
conformance suite and load smoke test before promoting the recovered data.
Record restore duration, replay-chain verification, and the first successful
readiness timestamp as recovery objectives.

### Replay anchor retention and certification

Use an S3 bucket with Object Lock in **COMPLIANCE** mode, owned by a separate
audit account, for production anchors. The runtime database, application
account, and its persistent volumes are not acceptable anchor stores.
Configure the release writer only to add a new immutable object, and use a
separate audit-reader identity with no delete or retention-bypass permission.

Before a release or recovery drill, a platform administrator creates a
checkpoint with `POST /admin/replay/anchor` and writes the returned JSON
unchanged to the audit bucket. Record the object location with the release
evidence. The anchor endpoint records its creation in the replay log before
signing the checkpoint, so the returned anchor certifies that governance
event as well.

To certify a rollback, download the retained JSON object with the audit-reader
identity and run:

```bash
REPLAY_ANCHOR_FILE=/secure/replay-anchor.json \
GAS_URL=https://gas.example.com GAS_TOKEN=<auditor-access-token> \
NAMESPACE=governed-autonomy RELEASE=governed-autonomy REVISION=<known-good> \
bash deploy/scripts/rollback-smoke.sh
```

The script calls `POST /audit/replay/certify` after rollout and fails unless
the trusted anchor exactly matches the restored replay digest, head hash, and
frame count. For a disconnected recovery environment, retain the anchor
signer's public key alongside the object and run:

```bash
gas replay certify restored-replay.jsonl \
  --anchor /secure/replay-anchor.json \
  --public-key <base64url-ed25519-public-key>
```

Set `GAS_REPLAY_ANCHOR_FILE` and
`GAS_REQUIRE_REPLAY_CERTIFICATION=true` for the deployed load smoke check.
The post-deploy token must have the `Auditor` role in OIDC-only deployments;
the static health-probe token cannot certify replay state.

With a local signer, the runtime Secret provides `url`, `issuer-key-id`, and
`issuer-private-key`; the issuer private key is raw 32-byte Ed25519 material
encoded as URL-safe base64. KMS mode provides `url` and uses workload identity
instead of an issuer private key. Trust keys and revocations are stored in the
PostgreSQL `trust_keys` table, so all replicas share rotation state.

For KMS-backed issuance, archive each key ID and raw Ed25519 public key in the
same independent Object Lock retention domain before switching the deployment
to a new KMS key. Add the new public key to the live trust store, deploy the
new `GAS_ISSUER_KMS_KEY_ID`, and retain the old live trust entry through the
maximum artifact lifetime. Revoke the old issuer key once that lifetime has
passed, but retain its archived public key for offline verification of
historical anchors.
