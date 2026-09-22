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
