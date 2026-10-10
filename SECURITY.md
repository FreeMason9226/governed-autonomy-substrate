# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities through a private GitHub Security
Advisory for this repository. Do not include exploit details in a public issue.
If private advisories are unavailable, contact the repository maintainers
through GitHub and request a private reporting channel.

Include the affected version or commit, impact, reproduction steps, and any
suggested mitigation. Please allow maintainers time to investigate and
coordinate a fix before publicly disclosing a vulnerability.

## Supported versions

The project is in pre-1.0 development. Security fixes are made against the
current development branch; users should upgrade to the latest published
release and review the changelog.

## Policy registry security

Policy content is canonicalized and hashed before publication. Registry records bind
the policy ID, semantic version, digest, schema version, signing timestamp, and
authority identity with an Ed25519 signature. A policy cannot be activated when its
digest or trusted signature fails verification, and revoked versions are fail-closed.
Use a KMS/HSM-backed signer and a durable, access-controlled backend in production;
the local development signer and filesystem backend are not a substitute for
independent WORM retention.
