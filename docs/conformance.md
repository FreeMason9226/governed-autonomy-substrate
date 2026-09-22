# GAS Protocol Conformance Specification & Test Suite

## Overview

The **Governed Autonomy Substrate (GAS)** defines a cryptographically verifiable, append-only-audited execution barrier for autonomous AI agent actions. To ensure complete interoperability across heterogeneous environments and programming languages (Go, TypeScript, Rust, Java, Python, C#), the GAS project maintains a language-agnostic conformance test suite.

This document describes:
1. Conformance levels defined in [SPEC.md](../SPEC.md) (§15).
2. The structure and schemas of test vector suites in `tests/conformance/vectors/`.
3. How alternative implementations consume and execute the test vectors.
4. Guidelines for submitting and certifying conformance.

---

## Conformance Levels

Implementations of the GAS protocol are evaluated against three progressive conformance levels:

| Level | Name | Scope & Requirements | Primary Use Case |
|---|---|---|---|
| **Level 1** | **Basic Authorization** | • Canonical JSON encoding ([SPEC.md §3](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#3-canonical-json))<br>• Ed25519 signature generation & verification ([SPEC.md §2](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#2-cryptographic-primitives))<br>• GAA wire format parsing & validation ([SPEC.md §4](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#4-governance-authorization-artifact-gaa))<br>• Wall-clock expiry & basic nonce check | Edge clients, lightweight agent SDKs, client-side verifiers |
| **Level 2** | **Full Execution Barrier** | • All Level 1 requirements<br>• Replay frame hash chaining & SHA-256 links ([SPEC.md §8](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#8-replay-frame))<br>• At-most-once atomic nonce consumption<br>• Frame reference & payload equality verification ([SPEC.md §13](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#13-execution-barrier-invariants))<br>• Authorization and Execution event logging ([SPEC.md §11](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#11-authorization-event), [§12](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#12-execution-event)) | Tool gateways (e.g., MCP gateway), sidecars, service proxies |
| **Level 3** | **Governed Platform** | • All Level 1 and Level 2 requirements<br>• Deterministic policy arbiter evaluation ([SPEC.md §6](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#6-policy-definition), [§14](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#14-arbiter-decision))<br>• Signed policy manifests with monotonic versioning ([SPEC.md §7](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#7-signed-policy-manifest))<br>• Trust store snapshot management and key revocation ([SPEC.md §9](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#9-trust-store-snapshot))<br>• Multi-party signed approval quorums ([SPEC.md §5](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#5-signed-approval)) | Enterprise governance servers, compliance runtimes, platform orchestrators |

---

## Conformance Test Vectors

All conformance test vectors reside in [`tests/conformance/vectors/`](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/tests/conformance/vectors/). These files are standard JSON documents containing inputs and expected outputs.

### 1. Canonical JSON (`canonical_json.json`)
- **Spec Section:** [SPEC.md §3](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#3-canonical-json)
- **Purpose:** Verifies that JSON serialization produces deterministic byte representations across all runtimes.
- **Key Rules Verified:**
  - Lexicographical sorting of object keys by Unicode code point order.
  - Compact token separators (`,`, `:` with no whitespace).
  - Unescaped UTF-8 string encoding (`ensure_ascii=False`).
  - Arrays preserve element order and are not sorted.
  - Correct formatting of primitives (integers, booleans, null).
- **Test Runner Expectation:** Encode `input` and compare byte-for-byte against `expected_utf8` and `expected_hex`.

### 2. Governance Authorization Artifact (`gaa.json`)
- **Spec Section:** [SPEC.md §4](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#4-governance-authorization-artifact-gaa)
- **Purpose:** Validates GAA wire format parsing, canonical unsigned payload construction, and Ed25519 signature verification.
- **Test Categories:**
  - `valid_vectors`: Valid GAAs signed with known Ed25519 test keys. Tests assert exact unsigned payload string, SHA-256 digest, signature verification, and round-trip preservation.
  - `invalid_vectors`: Strict negative test cases ensuring implementations reject:
    - Extra undeclared fields (`expected_error: "extra_fields"`).
    - Missing required fields (`expected_error: "missing_field"`).
    - Boolean alias for integers such as `expires_at: true` (`expected_error: "invalid_expires_at"`).
    - Empty string identifiers (`expected_error: "empty_string"`).
    - Tampered payloads with invalid signatures (`expected_error: "invalid_signature"`).

### 3. Signed Approval (`signed_approval.json`)
- **Spec Section:** [SPEC.md §5](file:///c:/Users/fathead/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#5-signed-approval)
- **Purpose:** Validates multi-party quorum approval tokens and request binding.
- **Key Rules Verified:**
  - Canonical unsigned payload construction where `actor_id` defaults to `null` and `context` defaults to `{}` when omitted from wire format.
  - Request binding: When computing `request_digest`, the request MUST have the `"approvals"` field stripped before canonical JSON serialization to avoid circular dependencies.

### 4. Policy Definition & Digest (`policy_digest.json`)
- **Spec Section:** [SPEC.md §6](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#6-policy-definition)
- **Purpose:** Ensures policy definitions have identical canonical serialization and SHA-256 digest across all implementations.
- **Key Rules Verified:**
  - Sorting of actions, context fields, and approval action keys.
  - Deterministic digest generation for minimal and complex multi-action policies.

### 5. Replay Frame Hash Chaining (`replay_chain.json`)
- **Spec Section:** [SPEC.md §8](file:///c:/Users/fathe/OneDrive/Documents/Copilot/Created/governed-autonomy-substrate/SPEC.md#8-replay-frame)
- **Purpose:** Validates append-only log frame hashing and link integrity.
- **Key Rules Verified:**
  - Genesis frame has `previous_hash: ""`.
  - Frame hash formula: `SHA-256(canonical_json({"event": event, "frame_id": frame_id, "previous_hash": previous_hash}))`.
  - Sequential frame linking: Frame $N$'s `previous_hash` must equal Frame $N-1$'s `frame_hash`.
  - Detection of broken chains or tampered event payloads (fail-closed behavior).

---

## Implementing Conformance in Other Languages

To build a conformant GAS implementation in another language (e.g., Go, TypeScript, Rust, C#):

### Step 1: Clone Vectors
Include or submodule the `tests/conformance/vectors/` directory into your project repository.

### Step 2: Implement Canonical JSON
Before attempting cryptography or policy logic, ensure your Canonical JSON encoder matches all vectors in `canonical_json.json`:
```typescript
// Example: TypeScript verification
import vectors from "./vectors/canonical_json.json";

for (const vec of vectors.vectors) {
  const encoded = canonicalJson(vec.input);
  if (vec.expected_utf8) {
    assert.strictEqual(new TextDecoder().decode(encoded), vec.expected_utf8);
  }
}
```

### Step 3: Implement Ed25519 & GAA Parsing
- Ensure your base64 decoder supports URL-safe unpadded base64 (`RFC 4648 §5`).
- Ensure Ed25519 signature verification adheres to raw 32-byte public keys and 64-byte signatures.
- Validate against `gaa.json` and `signed_approval.json`.

### Step 4: Implement Hash Chaining & Policy Engine
- Validate against `policy_digest.json` and `replay_chain.json`.

---

## Continuous Conformance in CI

In this repository, conformance tests are automatically executed on every pull request and push across Python 3.11, 3.12, and 3.13 via GitHub Actions (`.github/workflows/ci.yml`):

```bash
# Run the complete conformance suite
python -m pytest tests/conformance/ -v
```

All 16 test cases must pass without warnings or errors.

---

## Adding New Conformance Vectors

Whenever new protocol features or edge cases are added:
1. Propose the protocol update via the RFC process described in [CONTRIBUTING.md](../CONTRIBUTING.md) and [`docs/rfc/template.md`](rfc/template.md).
2. Add new test vectors to the appropriate file under `tests/conformance/vectors/`.
3. Update `tests/conformance/test_conformance.py` to assert the new behavior.
4. Ensure all reference and third-party implementations pass before marking the RFC ratified.
