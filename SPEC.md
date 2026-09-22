# GAS Protocol Specification

## Version 1.0 — Governed Autonomy Substrate

**Status:** Draft  
**Protocol Version:** `1.0`  
**Reference Implementation:** [`governed-autonomy-substrate`](https://github.com/governed-autonomy/governed-autonomy-substrate) (Python ≥ 3.11)  
**License:** Apache 2.0

---

## Abstract

The Governed Autonomy Substrate (GAS) Protocol defines a cryptographically
verifiable, append-only-audited execution barrier for autonomous AI agent
actions. Before any action with side effects may execute, an authorized issuer
must produce a **Governance Authorization Artifact (GAA)** — a signed, expiring,
nonce-bound token that binds the action request to a deterministic policy
decision and a replay log frame. The execution barrier then verifies the GAA and
atomically claims its nonce, giving at-most-once semantics under concurrent
delivery.

The protocol is intentionally narrow: it defines wire formats, cryptographic
primitives, and invariants. It does not mandate transport, storage engine,
identity federation, or policy language beyond the schema defined here.

---

## Table of Contents

1. [Conventions](#1-conventions)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Canonical JSON](#3-canonical-json)
4. [Governance Authorization Artifact (GAA)](#4-governance-authorization-artifact-gaa)
5. [Signed Approval](#5-signed-approval)
6. [Policy Definition](#6-policy-definition)
7. [Signed Policy Manifest](#7-signed-policy-manifest)
8. [Replay Frame](#8-replay-frame)
9. [Trust Store Snapshot](#9-trust-store-snapshot)
10. [Policy Registry Snapshot](#10-policy-registry-snapshot)
11. [Authorization Event](#11-authorization-event)
12. [Execution Event](#12-execution-event)
13. [Execution Barrier Invariants](#13-execution-barrier-invariants)
14. [Arbiter Decision](#14-arbiter-decision)
15. [Conformance Levels](#15-conformance-levels)
16. [Error Codes](#16-error-codes)
17. [Security Considerations](#17-security-considerations)
18. [Change Process](#18-change-process)

---

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as described in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

All string values MUST be UTF-8 encoded. JSON examples use standard JSON
notation. Types are described as:

- `string` — JSON string
- `integer` — JSON number with no fractional part, no boolean alias
- `boolean` — JSON `true` or `false`
- `object` — JSON object
- `array` — JSON array
- `string (base64url-nopad)` — URL-safe base64 encoding without padding `=`
  characters (RFC 4648 §5, no padding)

---

## 2. Cryptographic Primitives

### 2.1 Signature Algorithm

All signatures in the GAS protocol use **Ed25519** (RFC 8037).

- Private key material MUST NOT be serialized in any GAS wire format.
- Public keys MUST be serialized as 32 raw bytes encoded as
  `string (base64url-nopad)`.
- Signatures MUST be serialized as 64 raw bytes encoded as
  `string (base64url-nopad)`.

### 2.2 Digest Algorithm

All digests in the GAS protocol use **SHA-256** (FIPS 180-4).

- Digests MUST be serialized as lowercase hexadecimal strings (64 characters).

### 2.3 Nonce Requirements

A nonce is an opaque, single-use string. Implementations:

- MUST generate nonces with at least 128 bits of entropy (e.g., UUID v4 or
  32 random hex characters).
- MUST reject any nonce that has been previously claimed (see §13).
- MUST NOT reuse nonces across process restarts; the nonce store MUST be
  durable.

---

## 3. Canonical JSON

The **Canonical JSON** encoding used throughout the protocol is defined as:

1. Serialize the value as JSON.
2. Object keys MUST be sorted lexicographically (Unicode code point order).
3. No whitespace between tokens (compact form).
4. Strings MUST be encoded without unnecessary escaping (`ensure_ascii=False`
   equivalent — Unicode characters are represented directly in UTF-8).
5. The result MUST be encoded as UTF-8 bytes.

This is equivalent to Python's:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

All payloads that are signed or digested MUST use Canonical JSON. Implementors
MUST verify that their canonical encoding produces byte-identical results against
the conformance test vectors in `tests/conformance/vectors/`.

---

## 4. Governance Authorization Artifact (GAA)

The GAA is the central artifact of the GAS protocol. It is a signed token that
authorizes exactly one execution of one action.

### 4.1 Wire Format

```json
{
  "action_request": <object>,
  "decision":       <object>,
  "expires_at":     <integer>,
  "nonce":          <string>,
  "replay_frame_ref": <string>,
  "issuer_key_id":  <string>,
  "signature":      <string (base64url-nopad)>
}
```

The wire form MUST contain exactly these seven fields — no more, no fewer.

### 4.2 Field Semantics

| Field | Type | Description |
| --- | --- | --- |
| `action_request` | object | The full, unmodified action request that was authorized. MUST include at minimum an `"action"` string field. |
| `decision` | object | The arbiter decision object (§14) produced for this request. |
| `expires_at` | integer | Unix timestamp (seconds since epoch, UTC) after which this GAA MUST be rejected. |
| `nonce` | string | A single-use random token (§2.3). Non-empty. |
| `replay_frame_ref` | string | The `frame_id` of the authorization replay frame that records this GAA's issuance. Non-empty. |
| `issuer_key_id` | string | The key ID of the Ed25519 signing key. Non-empty. |
| `signature` | string | Ed25519 signature over the canonical JSON of the unsigned payload (§4.3). Base64url-nopad. |

### 4.3 Signature Payload

The signed bytes are the Canonical JSON encoding of the object formed by the
GAA fields **excluding** `"signature"`:

```json
{
  "action_request": <action_request>,
  "decision":       <decision>,
  "expires_at":     <expires_at>,
  "issuer_key_id":  <issuer_key_id>,
  "nonce":          <nonce>,
  "replay_frame_ref": <replay_frame_ref>
}
```

Note: key order after Canonical JSON sorting is alphabetical.

### 4.4 Parsing Rules

An implementation parsing a GAA:

1. MUST reject the document if it is not a JSON object.
2. MUST reject the document if it does not contain exactly the seven required
   fields.
3. MUST reject the document if `action_request` or `decision` are not objects.
4. MUST reject the document if `expires_at` is not an integer or is a boolean.
5. MUST reject the document if `nonce`, `replay_frame_ref`, `issuer_key_id`, or
   `signature` are empty strings or not strings.

---

## 5. Signed Approval

A `SignedApproval` is a detached, cryptographically bound approval record
used to satisfy multi-party quorum requirements.

### 5.1 Wire Format

```json
{
  "action":          <string>,
  "request_digest":  <string (hex-sha256)>,
  "decision_digest": <string (hex-sha256)>,
  "issuer_key_id":   <string>,
  "signature":       <string (base64url-nopad)>,
  "actor_id":        <string | OMITTED>,
  "context":         <object | OMITTED>
}
```

Required fields: `action`, `request_digest`, `decision_digest`, `issuer_key_id`,
`signature`. Optional fields: `actor_id`, `context`.

### 5.2 Signature Payload

The signed bytes are the Canonical JSON encoding of:

```json
{
  "action":          <action>,
  "actor_id":        <actor_id or null>,
  "context":         <context>,
  "decision_digest": <decision_digest>,
  "issuer_key_id":   <issuer_key_id>,
  "request_digest":  <request_digest>
}
```

`actor_id` MUST be included as `null` if absent. `context` MUST be included as
`{}` if absent.

### 5.3 Request Binding

An approval binds to a request by `request_digest`, which is the SHA-256 hex
digest of the Canonical JSON of the request **with the `"approvals"` key
removed**. This prevents circular binding.

---

## 6. Policy Definition

A `Policy` is a data-only, deterministic policy input for authorization.

### 6.1 Wire Format

```json
{
  "policy_id":          <string>,
  "allowed_actions":    [<string>, ...],
  "required_fields":    { "<action>": [<string>, ...], ... },
  "exact_fields":       { "<action>": { "<field>": <value>, ... }, ... },
  "required_context":   [<string>, ...],
  "exact_context":      { "<field>": <value>, ... },
  "max_request_bytes":  <integer>,
  "max_ttl_seconds":    <integer>,
  "required_approvals": { "<action>": <integer>, ... }
}
```

`required_approvals` MAY be omitted; it defaults to `{}`.

### 6.2 Invariants

- `policy_id` MUST be a non-empty string.
- `allowed_actions` MUST be sorted lexicographically. Duplicates MUST NOT appear.
- `required_context` MUST be sorted lexicographically.
- `max_request_bytes` and `max_ttl_seconds` MUST be positive integers.
- `required_approvals` values MUST be non-negative integers.

### 6.3 Policy Digest

The canonical digest of a policy is the SHA-256 hex digest of the Canonical
JSON of the policy's wire-format object. The digest is stable across
implementations as long as Canonical JSON rules (§3) are followed.

---

## 7. Signed Policy Manifest

A `SignedPolicyManifest` binds a policy definition, version, and issuer
signature, enabling registries to accept only manifests verified by a trusted
authority.

### 7.1 Wire Format

```json
{
  "policy":        <policy object>,
  "version":       <integer>,
  "issuer_key_id": <string>,
  "signature":     <string (base64url-nopad)>
}
```

### 7.2 Signature Payload

```json
{
  "issuer_key_id": <issuer_key_id>,
  "policy":        <policy object>,
  "version":       <version>
}
```

### 7.3 Version Semantics

- `version` MUST be a positive integer.
- A registry MUST reject a manifest whose `version` is less than or equal to
  the currently registered version for the same `policy_id`, unless the digest
  is identical (idempotent re-registration).
- A registry MUST reject a manifest whose signature does not verify against a
  trusted issuer key.

---

## 8. Replay Frame

A `ReplayFrame` is the unit of the hash-chained append-only log.

### 8.1 Wire Format (JSONL)

Each frame is a single JSON object on its own line (no trailing whitespace):

```json
{"event":{...},"frame_hash":"<hex-sha256>","frame_id":"<string>","previous_hash":"<hex-sha256 or empty string>"}
```

### 8.2 Field Semantics

| Field | Type | Description |
| --- | --- | --- |
| `frame_id` | string | Unique identifier for this frame. Non-empty. |
| `previous_hash` | string | `frame_hash` of the preceding frame, or `""` for the genesis frame. |
| `event` | object | The event payload (§11, §12). |
| `frame_hash` | string | SHA-256 hex digest of the Canonical JSON of `{"event": ..., "frame_id": ..., "previous_hash": ...}`. |

### 8.3 Chain Invariants

On load, an implementation MUST:

1. Verify that each `frame_hash` equals the SHA-256 hex digest of the Canonical
   JSON of `{event, frame_id, previous_hash}` for that frame.
2. Verify that each frame's `previous_hash` equals the `frame_hash` of the
   immediately preceding frame (or `""` for the first frame).
3. Reject the entire log and fail closed if either invariant is violated.

---

## 9. Trust Store Snapshot

```json
{
  "keys":    { "<key_id>": "<base64url-nopad public key bytes>", ... },
  "revoked": ["<key_id>", ...]
}
```

- Keys are 32-byte Ed25519 public keys encoded as base64url-nopad.
- `revoked` entries MUST be a subset of `keys`.
- `revoked` MUST be sorted lexicographically.
- Implementations MUST reject a revoked key when resolving for signature
  verification.

---

## 10. Policy Registry Snapshot

```json
{
  "policies": [
    { "policy": <policy object>, "version": <integer> },
    { "policy": <policy object>, "version": <integer>, "issuer_key_id": "<string>", "signature": "<string>" }
  ]
}
```

Entries without `"signature"` are unsigned registrations. Entries with
`"signature"` are `SignedPolicyManifest` objects embedded inline.

---

## 11. Authorization Event

An authorization event is stored in a replay frame when an issuer produces (or
denies) a GAA.

```json
{
  "type":             "authorization",
  "nonce":            <string>,
  "issued":           <boolean>,
  "request":          <object>,
  "decision":         <object>,
  "artifact_payload": <object | null>
}
```

- `issued` is `true` if a GAA was produced; `false` if the request was denied.
- `artifact_payload` is the unsigned GAA payload object when `issued` is `true`;
  `null` otherwise.
- Denied requests MUST be recorded but MUST NOT produce a signed GAA.

---

## 12. Execution Event

An execution event is stored in a replay frame after the execution barrier
attempts to invoke the action callable.

```json
{
  "type":       "execution",
  "nonce":      <string>,
  "status":     "completed" | "failed",
  "result":     <string | null>,
  "error":      <string | null>,
  "policy_id":  <string | null>,
  "frame_ref":  <string>
}
```

- `status` MUST be `"completed"` on success or `"failed"` on any error.
- `result` is a bounded JSON representation of the action result, or `null`.
  Implementations MUST NOT store unbounded or secret action results.
- `error` is a bounded, sanitized error description, or `null`.
- `frame_ref` is the `frame_id` of the authorization frame for this nonce.

---

## 13. Execution Barrier Invariants

An execution barrier MUST enforce all of the following checks in order before
invoking the action callable:

1. **Signature validity** — The GAA signature MUST verify against the public key
   identified by `issuer_key_id` in the trust store. The key MUST NOT be
   revoked.
2. **Expiry** — `expires_at` MUST be greater than the current Unix timestamp
   (UTC). Implementations MUST use wall-clock time from a reliable source and
   MUST NOT use client-supplied time.
3. **Nonce uniqueness** — The nonce MUST NOT have been previously claimed.
4. **Frame reference** — A replay frame with `frame_id` equal to
   `replay_frame_ref` MUST exist in the log.
5. **Payload equality** — The `action_request` and `decision` fields in the GAA
   MUST exactly equal the `request` and `decision` fields of the referenced
   authorization frame event.
6. **Allow decision** — `decision.allow` MUST be `true`.
7. **Allowed action** — The action named in `action_request.action` MUST appear
   in `decision.allowed_actions`.
8. **Policy digest** (if a `PolicyRegistry` is present) — The policy identified
   by `decision.policy` MUST exist in the registry and its current digest MUST
   equal `decision.policy_digest`. The arbiter MUST be re-run over the exact
   request to re-enforce all policy constraints.

**Nonce claim MUST be atomic with the decision to execute.** If the nonce claim
fails (duplicate), the barrier MUST reject without executing. A failed execution
after nonce claim MUST NOT release or reuse the nonce; compensation MUST proceed
through a separate signed compensating GAA.

---

## 14. Arbiter Decision

The arbiter decision object is produced by a deterministic, stateless evaluator.

```json
{
  "allow":          <boolean>,
  "allowed_actions": [<string>, ...],
  "policy":         <string>,
  "policy_digest":  <string (hex-sha256)>,
  "reasons":        [<string>, ...],
  "reason_codes":   [<string>, ...],
  "request_digest": <string (hex-sha256)>
}
```

### 14.1 Reason Codes

Machine-readable denial reason codes:

| Code | Meaning |
| --- | --- |
| `action_not_allowed` | The requested action is not in `allowed_actions`. |
| `required_field_missing` | A field required by the policy for this action is absent. |
| `field_mismatch` | A field in the request does not match the exact value required by the policy. |
| `required_context_missing` | A required context key is absent. |
| `context_mismatch` | A context field does not match the policy's exact value. |
| `approval_quorum_not_met` | The number of valid, unique signed approvals is below the required quorum. |
| `request_too_large` | The Canonical JSON of the request exceeds `max_request_bytes`. |
| `invalid_context` | The `context` field is not an object. |

Implementations MAY add additional reason codes with a namespace prefix
(e.g., `vendor.rate_limit_exceeded`) but MUST NOT reuse the codes above with
different semantics.

---

## 15. Conformance Levels

### Level 1 — Basic Authorization

An implementation is **Level 1 conformant** if it:

- Produces and verifies GAAs with correct Ed25519 signatures.
- Enforces expiry, nonce uniqueness, and the allow decision.
- Uses Canonical JSON for all signing payloads.
- Produces byte-identical digests for the conformance test vectors.

### Level 2 — Full Barrier

An implementation is **Level 2 conformant** if it additionally:

- Maintains a hash-chained replay log with the frame format in §8.
- Enforces frame reference, payload equality, and allowed-action checks.
- Provides at-most-once nonce claim semantics under concurrent delivery.
- Records authorization and execution events (§11, §12).

### Level 3 — Governed Platform

An implementation is **Level 3 conformant** if it additionally:

- Implements the `Policy` schema (§6) and `DeterministicArbiter` (§14).
- Implements the `SignedPolicyManifest` schema (§7) with registry rollback
  protection.
- Implements the `TrustStore` snapshot (§9) with revocation.
- Re-runs the arbiter at execution time and verifies the policy digest.

---

## 16. Error Codes

HTTP adapters built on GAS SHOULD use the following status codes:

| Condition | HTTP Status |
| --- | --- |
| Invalid GAA (parse failure) | 400 Bad Request |
| Signature invalid or key revoked | 403 Forbidden |
| GAA expired | 403 Forbidden |
| Nonce already consumed | 409 Conflict |
| Frame reference not found | 422 Unprocessable Entity |
| Payload mismatch | 422 Unprocessable Entity |
| Decision is deny | 403 Forbidden |
| Policy digest mismatch | 422 Unprocessable Entity |
| Barrier check passed, action failed | 200 OK (with `status: failed` in body) |

---

## 17. Security Considerations

### Threat Model

The barrier assumes:

- Issuer private keys are provisioned through a trusted out-of-band channel.
- The process and replay log storage are not already compromised.
- Wall-clock time is obtained from a reliable source (not client-supplied).

### Canonical JSON and Signature Binding

Canonical JSON prevents equivalent representations from signing different bytes.
Implementations MUST verify their canonical encoding against the test vectors
before deploying.

### Nonce Reuse

Nonce reuse breaks at-most-once semantics. The nonce store MUST survive process
restarts. In-memory-only nonce stores MUST NOT be used in production.

### Replay Log Integrity

A broken hash chain MUST cause the log to fail closed — the implementation MUST
NOT accept a log with a chain break. Truncation or corruption MUST be detected
on load.

### Policy Digest Binding

The GAA binds the exact policy digest that was active at authorization time.
Re-running the arbiter at execution time against the current policy detects
any policy change between authorization and execution.

### Action Result Confidentiality

Action results in execution frames are audit data. Implementations MUST NOT
store sensitive data (secrets, credentials, PII) in execution frames.

### Revocation

Revoked keys MUST be rejected immediately. Old keys MAY be retained for
verification of already-issued artifacts during a rotation window, but the
trust store MUST mark them revoked.

---

## 18. Change Process

Changes to this specification follow the RFC process described in
[CONTRIBUTING.md](../CONTRIBUTING.md).

Wire format changes (any addition, removal, or semantic change to fields in
§4–§14) require a new protocol version. The version is communicated
out-of-band (e.g., in API metadata or registry configuration); individual
artifacts do not currently embed a version field. A future RFC may add a
`"gas_version"` field to the GAA wire format.

Non-breaking clarifications to existing field semantics MAY be made to this
document without incrementing the protocol version.
