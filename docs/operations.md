# Operations runbook

## Configuration

Never use the demo server with a default credential. Set
`GOVERNED_AUTONOMY_BEARER_TOKEN` from a secret manager, or integrate an
`OIDCValidator` with a provider-owned JWKS cache. TLS termination, ingress
authorization, key rotation, and network policy remain deployment controls.

## Migrations, backup, and disaster recovery

Apply `POSTGRES_NONCE_SCHEMA` and `POSTGRES_REPLAY_SCHEMA` through a reviewed,
versioned migration tool. Back up replay frames and policy/trust snapshots
with encryption and retention controls. Restore into an isolated environment,
verify the hash chain and signatures, then promote only after readiness checks.
Do not fabricate certificates, keys, or cloud credentials in this repository.

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

### Recovery drills

Run `deploy/scripts/rollback-smoke.sh` with an explicitly selected Helm
revision during each release exercise. Restore a recent dump in an isolated
PostgreSQL instance with `deploy/scripts/dr-restore-check.sh`, then run the
conformance suite and load smoke test before promoting the recovered data.
Record restore duration, replay-chain verification, and the first successful
readiness timestamp as recovery objectives.
