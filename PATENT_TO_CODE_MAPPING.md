# Patent-to-Code Mapping

This document maps the patent draft's principal technical concepts to the implementation in the Governed Autonomy Substrate repository.

## Coverage summary

The codebase implements the claim family around:
- mandatory governance bottleneck and execution-boundary enforcement
- deterministic arbitration and policy evaluation
- signed Governance Authorization Artifacts (GAAs)
- append-only replay evidence with tamper detection
- governance registry / policy provenance
- policy scope (actor, tenant, request size, TTL)
- federated governance synchronization and reconciliation

## Core architecture mapping

### 1. Mandatory governance bottleneck and execution-boundary enforcement

Patent concepts:
- mandatory governance bottleneck
- execution systems reject absent/invalid GAA
- execution layer structurally incapable of generating valid GAA

Code:
- `src/governed_autonomy/engine.py` — `ExecutionBoundary`
- `src/governed_autonomy/issuer.py` — `AuthorizationIssuer`, `PolicyDeniedError`
- `src/governed_autonomy/models.py` — `GovernanceAuthorizationArtifact`
- `src/governed_autonomy/trust.py` — `TrustStore`
- `src/governed_autonomy/mesh.py` — `GovernanceSourceRegistry`

Implementation notes:
- `ExecutionBoundary._validate()` verifies signature, expiry, nonce, replay reference, policy decision, issuer trust, and request policy compatibility.
- `ExecutionBoundary.execute()` consumes the nonce before invoking the action.
- The execution boundary rejects actions without a valid signed GAA.
- TrustStore enforces issuer registration/revocation and supports rotation.
- `GovernanceSourceRegistry` provides canonical JSON snapshots for mesh-source trust configuration, allowing a local trusted source map to be persisted and reloaded while keeping public keys in a reproducible, auditable form.

### 2. Deterministic arbitration and policy evaluation

Patent concepts:
- deterministic arbiter selection
- rule set evaluation
- policy decision outputs
- stable reasons and policy digests

Code:
- `src/governed_autonomy/policy.py` — `Policy`, `DeterministicArbiter`, `PolicyRegistry`

Implementation notes:
- `DeterministicArbiter.decide()` evaluates action, field, context, and request-size constraints.
- `Policy` includes canonical serialization and `digest()` for provenance.
- `PolicyRegistry` enforces immutable-by-ID policy definitions and digest stability.
- Policy decision output includes `policy_digest`, `request_digest`, and structured `reason_codes`.

### 3. Governance Authorization Artifact (GAA)

Patent concepts:
- signed GAA encoding governance decision, policy state, replay frame ref, expiration, nonce
- issuance by governance layer only
- strict validation at execution boundary

Code:
- `src/governed_autonomy/models.py` — `GovernanceAuthorizationArtifact`
- `src/governed_autonomy/issuer.py` — `AuthorizationIssuer.authorize()`

Implementation notes:
- `GovernanceAuthorizationArtifact` canonicalizes JSON and signs the unsigned payload with Ed25519.
- `from_dict()` and `from_json()` enforce strict schema validation.
- `AuthorizationIssuer.authorize()` appends a governance authorization frame, then signs the exact payload.

### 4. Replay buffer, audit trail, tamper detection, and durable evidence

Patent concepts:
- immutable replay frames
- append-only audit log
- divergence verification and tamper-evident evidence
- execution evidence with result digest and status

Code:
- `src/governed_autonomy/replay.py` — `ReplayLog`, `SQLiteReplayLog`, `ReplayFrame`

Implementation notes:
- Each replay frame is hash-chained and verified on load.
- `SQLiteReplayLog` persists frames and consumed nonces.
- `ReplayLog.events()` and `events_for_nonce()` provide filtered audit access.
- execution frames include authorization linkage and status metadata.
- failed actions produce failed execution frames with bounded error detail.
- result digest metadata prevents unbounded log growth.

### 5. Governance Intelligence Registry (GIR) and governance object synthesis

Patent concepts:
- GIR ingesting governance sources
- obligation extraction, field mapping, governance object generation
- constraint synthesis injection

Code:
- `src/governed_autonomy/governance.py` — `GovernanceRule`, `GovernanceRuleTranslator`

Implementation notes:
- `GovernanceRuleTranslator.translate()` converts governance statements into deterministic machine-enforceable `Policy` definitions.
- Governance rules include required fields and exact-field constraints and may be merged deterministically.
- This is a minimal but auditable first implementation of the GIR-style translation layer.

### 6. Policy registry and provenance

Patent concepts:
- policy versioning and provenance
- registry integrity and stable policy identity
- stale policy detection

Code:
- `src/governed_autonomy/policy.py` — `PolicyRegistry`

Implementation notes:
- `PolicyRegistry.register()` rejects policy ID reuse with different digests.
- `Policy.digest()` binds canonical policy contents to version/provenance.
- `ExecutionBoundary` can optionally verify exact policy digest matches before execution.

### 7. Scope constraints: actor, tenant, size, TTL

Patent concepts:
- governance rule set includes contextual constraints
- size and lifetime constraints are policy-controlled
- context-specific authorization

Code:
- `src/governed_autonomy/policy.py`

Implementation notes:
- `Policy` supports `required_context`, `exact_context`, `max_request_bytes`, and `max_ttl_seconds`.
- `DeterministicArbiter.decide()` enforces missing/mismatched context and request-size constraints.
- `AuthorizationIssuer.authorize()` rejects TTL values exceeding the policy maximum.

### 8. Governance service facade

Patent concepts:
- application-level authorization execution boundary
- service-level governance enforcement

Code:
- `src/governed_autonomy/service.py` — `GovernedService`
- `src/governed_autonomy/platform.py` — `GovernancePlatform`

Implementation notes:
- `GovernedService` binds policy IDs and named executable handlers.
- It blocks unknown policies and unknown action names before a nonce is consumed.
- It can bind a shared source registry into the authorization issuer so runtime mesh-preflight trust is configured once and reused across the service boundary.
- `GovernancePlatform.authorize(..., mesh_inputs=...)` exposes the same trust path at the platform layer, combining runtime policy validation and mesh evidence verification before issuance.
- `platform_report()` now includes mesh-source registry state and `health_report(..., mesh_source_registry=...)` records source counts and revoked-source state in the runtime health snapshot.
- It supports `execute_dict()` and `execute_json()` for serialized GAA execution.

### 9. Federated governance synchronization and reconciliation

Patent concepts:
- multi-organization governance fabric
- cross-organization governance synchronization
- reconciliation with conflicts and signed sync events

Code:
- `src/governed_autonomy/federation.py`

Implementation notes:
- `SignedSyncEvent` and `GovernanceSyncEnvelope` provide canonical signed sync payloads.
- `RegistrySnapshot` gives a deterministic summary of the local registry.
- `GovernanceReconciler` detects identical, newer, conflicting, and unknown policy states.
- Reconciliation is designed to fail on signature errors, stale nonces, unknown orgs, and policy conflicts.

## Claim families represented in code

### Independent and near-independent claim groups

1. Mandatory governance bottleneck / execution-boundary verification
   - `engine.py`, `issuer.py`, `models.py`, `trust.py`

2. Deterministic arbitration / policy rule evaluation
   - `policy.py`

3. GAA issuance and verification
   - `models.py`, `issuer.py`, `engine.py`

4. Replay / evidence / audit system
   - `replay.py`

5. Governance Intelligence Registry / synthesis
   - `governance.py`

6. Multi-organization federated governance
   - `federation.py`

## Practical implementation status

This repository is a working MVP, not a full commercial implementation. It captures the core claim architecture and deliberately emphasizes:
- production-sensible cryptographic signing
- canonicalized data structures
- explicit audit metadata
- deterministic policy evaluation
- fail-closed validation paths
- reconciliation safety without silent drift

## Recommended next additions

To further align with the patent draft, the next strongest refinements would be:
1. stronger governance-mesh node abstraction and weighted harmonization
2. explicit GIR snapshot versioning and signed registry publication
3. richer multi-org sync policy propagation with trust domains
4. replay/rollback certification and verification endpoints
5. a public `README` architecture diagram matching the patent figures

## Repository pointers

Key files:
- `src/governed_autonomy/engine.py`
- `src/governed_autonomy/issuer.py`
- `src/governed_autonomy/policy.py`
- `src/governed_autonomy/replay.py`
- `src/governed_autonomy/governance.py`
- `src/governed_autonomy/federation.py`
- `tests/test_federation.py`

This mapping is intended as a traceability document between the draft claims and the implementation, not as legal advice or an assertion that every claim is fully reduced to production code.

### 7. Governance mesh harmonization and predictive preflight

Patent concepts:
- multiple governance inputs contributing to a canonical decision
- weighted or prioritized governance source harmonization
- conflict detection before execution
- deterministic governance decision provenance and replay metadata

Code:
- `src/governed_autonomy/mesh.py` - `GovernanceInput`, `GovernanceMesh`, `GovernancePreflightDecision`

Implementation notes:
- Inputs require unique source IDs, positive weights, non-negative priorities, and a boolean `allow` decision.
- Exact canonical decision digests make equivalent inputs group deterministically.
- Weighted decision ranking uses stable weight, priority, and digest ordering.
- Conflicting allow/deny inputs at the highest priority fail closed with explicit conflict metadata.
- Optional `ReplayLog` integration appends a `governance_preflight` frame containing request, input, decision, and digest metadata.
- This is a bounded preflight/harmonization implementation; it does not claim predictive analytics, learned risk scoring, or external source attestation.

### 8. Replay divergence verification

Patent concepts:
- deterministic replay verification
- divergence/tamper detection after evidence capture
- auditable replay state certification

Code:
- `src/governed_autonomy/replay.py` - `ReplayLog.verify_integrity()`

Implementation notes:
- Recomputes every frame hash and previous-hash link without mutating the log.
- Reports a stable replay digest, head hash, frame count, duplicate IDs, and first detected integrity error.
- Audit event queries return detached copies so callers cannot mutate retained evidence through a returned object.
- This is local integrity evidence; external WORM storage, signed attestations, and cross-node comparison remain deployment responsibilities.

### 9. Governance mesh insertion before authorization

Patent concepts:
- governance-source harmonization before execution authorization
- canonical decision provenance carried into authorization evidence
- fail-closed governance conflict handling

Code:
- `src/governed_autonomy/issuer.py` - optional `mesh_inputs` authorization gate
- `src/governed_autonomy/service.py` - service facade propagation
- `tests/test_issuer.py` - allow/deny mesh integration coverage

Implementation notes:
- The mesh evaluates the exact request after approval evidence is attached and before nonce/artifact issuance.
- The mesh decision digest is bound into the signed GAA decision and authorization replay frame.
- Denied or conflicted mesh results are audited and raise `PolicyDeniedError`.
- Issued mesh-enabled authorization frames retain canonical `GovernanceInput` evidence and the request digest; `ExecutionBoundary` reconstructs and compares that evidence before execution, failing closed on malformed, conflicting, tampered, mismatched, or digest-divergent evidence.
- The integration is opt-in for compatibility; mandatory deployment policy can require callers to provide mesh inputs at a higher platform layer. This execution-side verification is local replay-bound evidence, not external source attestation or tamper-proof storage; legacy artifacts without mesh inputs remain compatible.
- `GovernanceInput.attest()`, `GovernanceSourceRegistry`, and `GovernanceMesh(trusted_sources=...)` add opt-in source signature verification, explicit registration/revocation semantics, and source-ID-to-key binding. This remains a local trust-registry adapter boundary and does not provide network identity, key rotation, or protected external retention.
