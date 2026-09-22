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

Implementation notes:
- `ExecutionBoundary._validate()` verifies signature, expiry, nonce, replay reference, policy decision, issuer trust, and request policy compatibility.
- `ExecutionBoundary.execute()` consumes the nonce before invoking the action.
- The execution boundary rejects actions without a valid signed GAA.
- TrustStore enforces issuer registration/revocation and supports rotation.

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

Implementation notes:
- `GovernedService` binds policy IDs and named executable handlers.
- It blocks unknown policies and unknown action names before a nonce is consumed.
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
