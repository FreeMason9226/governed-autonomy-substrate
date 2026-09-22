# NIST AI RMF 1.0 & NIST IR 8596 Compliance Profile

## Executive Summary

The **National Institute of Standards and Technology (NIST) Artificial Intelligence Risk Management Framework (AI RMF 1.0)** and **NIST IR 8596 (Cybersecurity Framework Profile for Artificial Intelligence)** articulate guidelines for managing risks in artificial intelligence systems.

The **Governed Autonomy Substrate (GAS)** serves as an architectural control implementation for autonomous AI agents. This document provides an itemized mapping demonstrating how GAS technical mechanisms satisfy the four core functions of the NIST AI RMF: **GOVERN**, **MAP**, **MEASURE**, and **MANAGE**.

---

## 1. Core Function Mapping

```
┌────────────────────────────────────────────────────────────────────────┐
│                        NIST AI RMF 1.0 CORE                            │
├───────────────┬───────────────┬────────────────┬───────────────────────┤
│    GOVERN     │      MAP      │    MEASURE     │        MANAGE         │
├───────────────┼───────────────┼────────────────┼───────────────────────┤
│ Policies,     │ Scope,        │ Metrics,       │ Execution Barrier,    │
│ Trust Store,  │ Context,      │ Append-Only    │ Nonce Atomicity,      │
│ Roles & Keys  │ Field Bounds  │ Replay Chains  │ Quorum Approvals      │
└───────────────┴───────────────┴────────────────┴───────────────────────┘
```

### 1.1 GOVERN (GV)
*Cultivating and implementing a culture of risk management within organizations designing, developing, deploying, or acquiring AI systems.*

| NIST Subcategory | Description | GAS Implementation & Mechanism |
|---|---|---|
| **GV-1.1** | Legal and regulatory requirements are understood and managed. | `PolicyRegistry` enables organizations to codify legal and enterprise constraints as deterministic rules before agent activation. |
| **GV-1.2** | Roles and responsibilities for AI risk management are defined and documented. | Asymmetric Ed25519 key management (`KeyPair`, `TrustStore`) clearly separates authorizers, administrators, approvers, and execution runtimes. |
| **GV-2.1** | Policies, processes, and procedures are in place to define risk thresholds. | `Policy` data objects enforce explicit action whitelists (`allowed_actions`), payload byte limits (`max_request_bytes`), and time-to-live ceilings (`max_ttl_seconds`). |
| **GV-3.1** | Mechanisms are in place for ongoing monitoring of policies and risks. | Signed policy manifests (`SignedPolicyManifest`) enforce cryptographic version monotonicity and prevent rollback attacks. |
| **GV-4.2** | Third-party and multi-agent risks are managed. | The `TrustStore` provides cryptographic public key tracking and immediate, durable key revocation for third-party tools or external agents. |

---

### 1.2 MAP (MP)
*Establishing context and understanding risks related to AI systems.*

| NIST Subcategory | Description | GAS Implementation & Mechanism |
|---|---|---|
| **MP-1.1** | Intended purpose, context, and operational environment are identified. | `MCPGatewayContext` and runtime context dictionaries bind tenant ID, agent ID, session ID, and deployment environment directly to each request. |
| **MP-2.2** | System requirements and constraints are identified. | `required_fields` and `exact_fields` policy constraints define strict schemas for every permitted agent action. |
| **MP-3.1** | Likelihood and consequences of negative AI impacts are categorized. | High-consequence actions (e.g. database deletions, fund transfers) are configured with `required_approvals > 0` requiring detached multi-party sign-offs. |

---

### 1.3 MEASURE (MS)
*Employing quantitative, qualitative, or other tools to assess AI risks.*

| NIST Subcategory | Description | GAS Implementation & Mechanism |
|---|---|---|
| **MS-1.1** | Approaches and metrics for risk measurement are established and validated. | Every authorization and execution event is tracked in the immutable `ReplayLog`. |
| **MS-2.3** | AI system performance and compliance are continuously tracked. | `ReplayLog.audit_summary()` reconstructs complete decision histories, tracking frame counts, authorization counts, execution counts, and failure rates. |
| **MS-3.2** | Integrity and security of AI telemetry and logs are maintained. | Hash-chained frames (`ReplayFrame`) where each frame hash is a SHA-256 digest linked to the preceding frame hash. Chain tampering is automatically detected on load. |
| **MS-4.1** | Test suites and evaluation procedures are maintained. | The 5-suite language-agnostic conformance harness ([`docs/conformance.md`](../conformance.md)) ensures that all runtimes compute byte-identical digests and signatures. |

---

### 1.4 MANAGE (MN)
*Allocating resources and applying controls to neutralize or remediate AI risks.*

| NIST Subcategory | Description | GAS Implementation & Mechanism |
|---|---|---|
| **MN-1.1** | Risks are addressed, mitigated, or accepted. | The `ExecutionBoundary` acts as an absolute, fail-closed barrier. Actions lacking a valid GAA cannot execute. |
| **MN-2.2** | Safeguards against unintended actions or runaways are active. | Single-use nonces (`nonce`) claimed atomically guarantee **at-most-once execution**, preventing infinite agent loops or replayed tool invocations. |
| **MN-3.1** | Multi-stakeholder oversight and human-in-the-loop controls are enforced. | `SignedApproval` allows designated human operators or security officers to issue detached cryptographic approvals required for quorum-gated actions. |
| **MN-4.2** | Incidents are recorded, reviewed, and compensated. | Interrupted or failed transactions are recorded as `failed` execution events, with compensation handled via explicit compensating GAAs. |

---

## 2. Alignment with NIST IR 8596 (Cybersecurity Profile for AI)

NIST IR 8596 extends the NIST Cybersecurity Framework (CSF 2.0) to AI systems. GAS directly fulfills the following technical profile subcategories:

1. **Protect - Access Control (PR.AC)**:
   - GAS enforces cryptographically authenticated authorization tokens (GAAs) signed with Ed25519, eliminating reliance on ambient in-process permissions.
2. **Protect - Data Security (PR.DS)**:
   - Nonces and replay frames prevent replay attacks, unauthorized action re-transmission, and man-in-the-middle tampering between LLM decision and tool execution.
3. **Detect - Adverse Event Detection (DE.AE)**:
   - Chain verification checks (`ReplayLog.verify_chain()`) immediately detect any modification, truncation, or substitution in the execution audit log.
4. **Respond - Incident Management (RS.MI)**:
   - Durable revocation state (`TrustStore.revoke`) invalidates compromised agent keys across the substrate instantaneously.
