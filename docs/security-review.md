# Security Review Scope

This repository does not claim to have completed an external penetration test. The
required review scope is:

- prove execution images contain no private signing key or KMS credential;
- attempt direct GAA signing and replay writes with execution-node identities;
- replay, alter, reorder, and truncate replay frames and verify fail-closed behavior;
- forge, reuse, expire, and cross-subject signed identity attestations;
- bypass policy registry proposal/quorum and separation-of-duties checks;
- test KMS timeout, rotation, stale public key, and audit-log failure modes;
- test Kubernetes NetworkPolicy and service-account permissions in a staging cluster.

The automated local evidence is in the focused CI security gate. An external assessor must
attach their report, scope, date, tool versions, and remediation status to the release
checklist before production or legal reliance.