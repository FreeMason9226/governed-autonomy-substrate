# Production assurance evidence

This repository produces implementation evidence; it does not certify compliance.
Control owners must retain the generated evidence in their approved records system
and evaluate it against their own SOC 2 and ISO/IEC 27001 scope.

## Audit anchoring

`ReplayLog.anchor(signer, sink)` signs the verified replay head and writes it to
an `AuditAnchorSink`. Configure a sink that is independently administered from
the runtime replay database (for example, immutable object retention or a
transparency-log adapter). The included `JSONLAuditAnchorSink` is an adapter
for separately retained storage, not a WORM service by itself. Each anchor
contains the frame count, head hash, replay digest, signer key ID, and signature;
verify it against the managed public key during restoration and investigation.
`ReplayLog.verify_anchor(anchor, public_key)` verifies both that signature and
that all checkpoint fields match the current, valid replay state. It intentionally
returns false after later frames are appended, so retain the checkpointed evidence
for historical comparisons.

## SOC 2 and ISO/IEC 27001 evidence

`ComplianceAuditor.evidence_bundle()` emits replay-integrity evidence, a
redacted audit summary, policy digests, trust-key inventory, and control
status records for SOC 2 CC6.1/CC7.2 and ISO/IEC 27001:2022 A.5.18/A.8.15.
It deliberately does not export authorization request or execution payloads.

Retain the evidence bundle with the independently stored audit anchor, policy
change approvals, identity-role assignment events, backup/restore drill
results, and access-review records. These operational records remain necessary
to demonstrate control operation.

## High availability and tracing

Use `PostgresOIDCSessionRepository` with browser OIDC flows and
`PostgresRateLimiter` for shared, fail-closed limits across API replicas.
The API accepts a `TraceRecorder` and propagates validated W3C `traceparent`
context without recording request bodies or authorization headers.

## Release provenance

Release tags run GitHub's signed artifact-attestation workflow over the release
checksum manifest. Downloaders can verify the resulting provenance with
`gh attestation verify SHA256SUMS --repo FreeMason9226/governed-autonomy-substrate`.
