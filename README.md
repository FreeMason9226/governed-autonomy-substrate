# Governed Autonomy Substrate (MVP)

This repository contains the first working slice of a governance authorization and execution barrier. It issues a signed **Governance Authorization Artifact (GAA)**, records the authorization as an append-only replay frame, and permits an action callable to run only after every barrier check succeeds.

## Architecture

1. `GovernanceAuthorizationArtifact` binds an action request, policy decision, expiry, nonce, replay-frame reference, issuer key ID, and Ed25519 signature using canonical JSON.
2. `ReplayLog` stores hash-chained frames. Its `load_jsonl` recovery path verifies every frame and reconstructs consumed nonces; `SQLiteReplayLog` persists those frames and consumed nonces transactionally across process restarts and fails closed if its stored chain is invalid. Append and nonce-claim operations are serialized for concurrent callers. An authorization frame captures the exact unsigned GAA payload and decision inputs; an execution frame records the result. `reconstruct_decisions()` and `audit_summary()` provide deterministic, replay-derived reconstruction of authorization history for audit and incident response.
3. `ExecutionBoundary` verifies the issuer signature, expiry, nonce uniqueness, referenced authorization frame, payload/frame equality, allow decision, and allowed-action constraint before atomically claiming the nonce and invoking the callable. With a `PolicyRegistry`, it also verifies the signed policy digest against the current trusted definition and re-runs the deterministic policy arbiter over the exact request to enforce `required_fields`, `exact_fields`, required/exact context, and size limits before execution. It records both completed and failed execution outcomes with bounded error metadata; successful results are hashed and only small JSON results are retained, preventing audit secrets and unbounded payloads. The atomic claim is locked for in-memory logs and transactional for SQLite, giving the barrier at-most-once authorization semantics under concurrent delivery; a failed action remains consumed and must be recovered through a separate compensating workflow.
4. `DeterministicArbiter` evaluates a request against a data-only `Policy`. Its output is stable for the same inputs and includes a canonical policy digest plus machine-readable denial reason codes, so clients do not need to parse human-readable prose and the exact policy contents are bound into the signed GAA decision rather than only a human-readable policy ID. `Policy.required_approvals` supports per-action approval quorum checks, allowing a request to carry a list of valid signed approvals and fail closed unless the required quorum is met.
5. `SignedApproval` is a detached, cryptographically bound approval record that carries the request digest, decision digest, signer key ID, actor context, and a valid Ed25519 signature. When the arbiter sees an `approvals` list, it verifies each signer and counts only valid, unique approvals toward the action's required quorum, which keeps the barrier fail-closed while allowing multi-party governance evidence.
6. `AuthorizationIssuer.authorize(..., approvals=...)` accepts signed approval evidence directly, binds those approvals into the authorization request, and records the authorization in the same append-only replay log as the artifact itself. This gives the issuer an explicit path for building multi-party governance authorizations without bypassing the execution barrier.
7. `RuntimeIdentity` and `GovernancePlatform` add the missing platform-shell layer: they bind service identity, environment, tenant, actor, and request metadata to a request before authorization, turning the barrier into a deployable runtime abstraction instead of only a local library. `PlatformDeploymentPolicy` additionally enforces allow-listed environments, tenant requirements, request IDs, source constraints, and runtime-context size limits so deploy-time guardrails fail closed before a signed GAA is issued.
8. `ServicePrincipal` and `ServicePrincipalRegistry` extend that layer with tenant-scoped service identities, explicit action/source/environment allowlists, and required-role checks, providing the missing identity-and-access boundary that a real platform needs before cross-tenant or privilege-escalation activity can reach the execution barrier.
9. `GovernancePlatform.authorize(..., mesh_inputs=...)` adds the runtime platform entrypoint for mesh-aware governance. It binds runtime context, deployment policy, and an optional `GovernanceSourceRegistry` so a platform service can authorize only after both the policy gate and the mesh-preflight evidence gate have passed.
10. `PolicyChangeManager` adds the missing governance operations layer: it can propose, approve, and activate policy rollouts with explicit quorum checks, so the platform has a path from policy review to safe runtime activation without bypassing the barrier.
10. `GovernanceRuleTranslator` converts human-readable governance statements such as `allow write_file when path is present and content is present` or `allow deploy when approvals >= 2` into canonical policy definitions, allowing policy authors to express intent in a machine-checkable form before issuing a signed GAA.
11. `AuthorizationIssuer` provides the end-to-end workflow: arbitrate, append an authorization frame, and issue a GAA. Denied requests are audited but never signed.
12. `TrustStore` manages issuer public keys and revocation. It supports retaining old keys during rotation while immediately blocking revoked issuers, validates its persisted schema on load, and atomically replaces its JSON file on update.
13. `GovernedService` binds policy IDs and action names to explicit application handlers, preventing callers from supplying arbitrary callables at execution time. It accepts `PolicyRegistry` directly (or converts the legacy dictionary form into one), can bind a shared `GovernanceSourceRegistry` into the issuer path for runtime mesh preflight, and exposes `audit_report()` for a deterministic snapshot of actions, policy IDs, replay health, and mesh-source trust status when configured.14. `GovernanceAuthorizationArtifact.from_dict` and `from_json` strictly parse transport representations, making `GovernedService.execute_dict` and `execute_json` suitable for a future HTTP or queue adapter without field coercion.15. `PolicyRegistry` prevents accidental reuse of a policy ID with different contents and exposes the canonical digest of every registered policy.
16. `SignedPolicyManifest` binds a policy definition, version, and policy-authority issuer signature; registries can accept only manifests verified by the trusted issuer store and reject stale/conflicting rollbacks. `PolicyRegistry` can also persist its signed-policy view to disk and rehydrate it on startup after validating the manifest signatures against the trust registry, and `to_dict()`/`from_dict()` provide a deterministic snapshot format for portable governance configuration.
17. `TrustStore.to_dict()` and `PolicyRegistry.to_dict()` expose JSON-friendly snapshots so a trusted issuer registry and policy set can be exported, verified, and reloaded without re-inventing the governance configuration. `GovernanceSourceRegistry.to_dict()` now does the same for mesh-source trust metadata, storing canonical base64 public keys and revocation state in a replay-safe snapshot that can be reloaded with `from_dict()`.
18. `ReplayLog.events` and `events_for_nonce` provide read-only audit queries for authorization and correlated execution outcomes without exposing storage internals. Execution frames include their authorization frame reference and policy ID.
19. `AuthorizationIssuer.authorize_compensation` issues a new, separately signed GAA only after an audited failed execution, linking the compensating request to the failed nonce instead of retrying the consumed artifact.
20. `health_report` provides a readiness-oriented structured check for replay integrity and configured trust/policy components.
21. `build_demo_service` wires the complete issuer, trust store, policy registry, boundary, replay log, and named action handler for integration use.
22. `AuthenticatedAPI` and `create_server` expose an authenticated standard-library HTTP boundary with `/health`, `/authorize`, and `/execute`, strict body limits, and JSON-only transport.

## Threat model and limitations

The boundary assumes issuer public keys are provisioned through a trusted channel and that the process and replay-log filesystem are not already compromised. Ed25519 provides authenticity and integrity, while canonical JSON prevents equivalent representations from signing different bytes. The JSONL log is append-only by API and hash-chained; SQLite adds durable frames and nonce indexing. The package now exposes integration boundaries for OIDC validation, remote signing, managed nonce storage, TLS, and rate limiting, but those controls still depend on correctly operated external providers. Action results are audit data and should not contain secrets. Execution is at-most-once at the authorization layer, not an end-to-end transactional guarantee for arbitrary external side effects.

The included arbitration layer is deliberately narrow: it supports allowed actions, required fields, exact field constraints, required/exact actor or scope context, approval quorum checks via `required_approvals`, a configurable canonical request-size limit, and a maximum authorization TTL. Policy definitions validate their names and deterministic ordering at construction and expose stable canonical digests; signed manifests are verified against a trusted local issuer store before the registry accepts them. It does not provide a general-purpose policy language, resource isolation, or semantic validation of action parameters. External identity validation and distributed nonce coordination are adapter boundaries, not substitutes for a managed identity provider or a highly available database deployment.

The service facade is intentionally in-process. A network adapter can translate authenticated requests into `authorize` and `execute` calls, but transport authentication and authorization remain deployment responsibilities.

The included HTTP adapter supports bearer authentication, request correlation, security headers, bounded rate limiting, and optional TLS wrapping through `create_server(..., tls=TLSConfig(...))`. It remains a minimal deployment boundary: token rotation, ingress policy, certificate lifecycle, identity federation middleware, WAF controls, and network-level authorization remain deployment responsibilities. The admin UI is a dependency-free operational surface, not a replacement for a full enterprise frontend with SSO, CSRF/session management, and granular operator permissions.

## Patent-to-code traceability

For the patent draft mapping, see [PATENT_TO_CODE_MAPPING.md](PATENT_TO_CODE_MAPPING.md).

## Run

```powershell
python -m pip install -e . pytest
python -m pytest
gas-demo
GOVERNED_AUTONOMY_BEARER_TOKEN=my-secret gas-server --host 0.0.0.0 --port 8000
```

`gas-demo` writes `replay.jsonl` in the current directory. `gas-server` starts the standard-library HTTP API with bearer-token auth for `/health`, `/audit`, `/authorize`, and `/execute`. For a production deployment, replace the in-memory replay index with a transactional durable store and provision public keys from a managed trust store.

## Production-sensible integration boundaries

The package now includes runnable boundaries for the next deployment slice:

* `OIDCValidator` validates compact JWTs fail-closed (issuer, audience, expiry, not-before, algorithm, key id, and signature) against an injectable `JWKSProvider`. A provider can implement `refresh()` to support key rotation without putting network policy in the validator.
* `LocalEd25519Signer` and `RemoteSigner` implement the `Signer` protocol. The remote boundary accepts only a callback and public key; private key material is never represented or serialized by this package.
* `SQLiteNonceRepository` performs transactional, unique nonce claims. `PostgresNonceRepository` and `POSTGRES_NONCE_SCHEMA` define the managed-database adapter boundary without making a PostgreSQL client a mandatory dependency.
* `TLSConfig`, bounded rate limiting, correlation IDs, and security headers are available to deployment code. The standard-library API supports `Bearer` authentication (and retains its legacy direct-token form), `/admin`, and read-only admin JSON slices for policies, proposals, and metrics.

These are integration-ready slices, not claims that this repository provisions an HSM, PostgreSQL cluster, OIDC discovery client, TLS certificate, or production ingress. Those must be supplied and operated by the deployment environment. The admin UI intentionally has no browser-side secret storage and all state-changing governance operations remain behind the existing signed service APIs.

## Production foundation artifacts

The repository also includes a durable SQLite job state model (`SQLiteJobStore`)
with idempotency, bounded retries, dead-letter state, and compensation hooks;
PostgreSQL replay/nonce schema and adapter boundaries; Prometheus text and
OpenTelemetry-compatible hooks; versioned `/api/v1` endpoints and
`/openapi.json`; and liveness/readiness/startup probes. `Dockerfile`,
`compose.yaml`, `deploy/kubernetes.yaml`, `deploy/helm/values.yaml`, and
`docs/operations.md` provide deployment and recovery starting points. They do
not provision a database, identity provider, certificates, backup system, or
cloud credentials.

## Multi-organization federation

The `federation` layer synchronizes policy registries without trusting remote state blindly. A `RegistrySnapshot` is a deterministic, canonical summary of policy entries and their individual digests; its content digest is portable across organizations while the source organization remains authenticated by the signed event. `SignedSyncEvent` binds the event type, source and target organizations, snapshot digest, per-policy digests, issuance timestamp, nonce, and signer key. `GovernanceSyncEnvelope` signs the complete event-plus-snapshot payload, preventing an intermediary from swapping either component.

`GovernanceReconciler` requires an explicit organization-to-key mapping and the same `TrustStore` used by the authorization substrate. It rejects unknown organizations, unregistered or revoked keys, invalid signatures, stale events, replayed nonces, snapshot tampering, unstable policy IDs, and policy digest mismatches. Identical content is a no-op; signed unknown policies can be imported; conflicting definitions for an existing `policy_id` produce explicit conflict metadata and are never silently merged. Policy manifests are independently verified before import, so federation signatures do not substitute for policy-authority trust.

This slice provides deterministic single-process reconciliation and an auditable result object. Production deployments still need durable consumed-event nonce storage, organization-key lifecycle/distribution, transport confidentiality, cross-region ordering/leases, and an external audit sink. The reconciler intentionally does not resolve conflicting policy definitions automatically.

## Governance mesh preflight

`GovernanceMesh` is the bounded governance-harmonization layer between independent governance sources and authorization. Each typed `GovernanceInput` carries a unique source ID, canonical decision, weight, priority, and optional metadata. The mesh groups equivalent decisions by SHA-256 of canonical JSON, ranks groups deterministically by total weight, priority, and digest, and returns a stable `GovernancePreflightDecision` with selected sources, input digests, reasons, and conflict metadata.

The mesh fails closed when highest-priority sources disagree on allow/deny. It can append a `governance_preflight` replay frame containing the request digest, input provenance, decision digest, and optional authorization-frame reference. This provides deterministic preflight evidence without replacing the signed GAA execution boundary. It is not predictive machine learning or an attestation system: production deployments still need authenticated source adapters, durable replay storage, source health/quality policy, and explicit handling for stale or unavailable external governance feeds.

## Replay divergence verification

`ReplayLog.verify_integrity()` provides deterministic replay evidence for audit and incident response. It rechecks every hash-chain link, detects duplicate frame IDs, and returns a stable replay digest, head hash, frame count, and first integrity error without mutating the log. `events()` and `events_for_nonce()` now return detached event copies, preventing callers from changing retained audit evidence accidentally.

This verifies local evidence only. A production deployment still needs external tamper-evident retention, signed replay attestations, cross-node comparison, and an operational response when divergence is detected.

### Mesh preflight at authorization

`AuthorizationIssuer.authorize(..., mesh_inputs=...)` optionally requires the deterministic governance mesh to preflight the exact canonical request before a GAA is issued. The resulting mesh digest is included in the signed decision and authorization replay frame. A denied or conflicted mesh result is audited as a denied authorization and never produces a GAA. Existing callers that omit `mesh_inputs` retain the original arbitration path; production deployments should supply authenticated governance-source adapters and treat mesh evidence as an additional gate, not a replacement for policy enforcement.

At execution, mesh-enabled authorization frames also carry the canonical, typed input evidence and request digest. `ExecutionBoundary` reconstructs the mesh from that replay-bound evidence and rejects malformed, conflicting, tampered, mismatched, or digest-divergent evidence before claiming the nonce or invoking the action. This is local replay evidence: deployments still need authenticated source adapters and durable, independently protected replay retention. Artifacts issued without `mesh_inputs` intentionally retain the legacy execution path.

`GovernanceInput.attest()` provides a compact source-adapter boundary: a source signs its canonical ID, decision, weighting, priority, and metadata, and `GovernanceMesh(trusted_sources={...})` verifies that signature and the source-ID-to-key binding before aggregation. `GovernanceSourceRegistry` adds explicit source registration, metadata, and revocation semantics for a platform-level mesh trust domain, and its JSON snapshot is canonicalized so the registry can be safely persisted and reloaded without exposing raw key material. This is an opt-in local trust registry, not a network identity provider or key-rotation service; deployments must provision and rotate trusted source keys securely.
