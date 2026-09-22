# EU AI Act Regulatory Compliance Profile

## Executive Summary

The **European Union Artificial Intelligence Act (Regulation (EU) 2024/1689)** establishes harmonized rules for the development, deployment, and operation of AI systems in the European Union. For autonomous agents operating in **high-risk applications** (Annex III) or functioning as general-purpose AI (GPAI) systems with systemic risk, strict requirements are imposed regarding risk management, record-keeping, transparency, human oversight, and cybersecurity.

The **Governed Autonomy Substrate (GAS)** provides an open technical execution barrier that directly satisfies key technical mandates of the EU AI Act.

---

## 1. Article-by-Article Regulatory Mapping

### Article 9: Risk Management System
> *"A risk management system shall be established, implemented, documented and maintained in relation to high-risk AI systems... It shall be understood as a continuous iterative process."*

#### GAS Technical Implementation:
- **Pre-Execution Policy Arbitration:** The `DeterministicArbiter` enforces policy boundaries prior to any action with external side effects. Actions not explicitly whitelisted in `allowed_actions` fail closed.
- **Parametric Constraint Verification:** Policies restrict acceptable input parameters using `exact_fields` and `required_fields`, eliminating hallucinated parameter injection.
- **Fail-Closed Default:** If an issuer key is unresolvable, a policy digest does not match, or an action is unrecognized, the execution barrier immediately halts execution without side effects.
- **Automated Compensation:** For multi-step workflows that experience partial failure, GAS supports explicit compensating GAAs with dedicated audit frames to maintain system consistency.

---

### Article 12: Record-Keeping (Automatic Logging)
> *"High-risk AI systems shall technically allow for the automatic recording of events ('logs') over the duration of the lifecycle of the system... [Logs] shall enable the detection of situations that may result in the AI system presenting a risk."*

#### GAS Technical Implementation:
- **Append-Only Replay Log:** `ReplayLog` and `SQLiteReplayLog` automatically record every authorization request, decision payload, GAA nonce, and execution outcome into a sequence of immutable `ReplayFrame` objects.
- **Cryptographic Hash Chaining:** Each replay frame includes a SHA-256 digest linked to the preceding frame hash (`previous_hash`). Any alteration, deletion, or truncation of log records invalidates the hash chain and causes the substrate to fail closed upon startup.
- **Non-Repudiation:** Authorization decisions are signed by authorized issuers using Ed25519 signatures, providing cryptographic non-repudiation of all governance decisions.
- **Deterministic Audit Reconstruction:** `ReplayLog.audit_summary()` deterministically reconstructs the state and nonces for all historical transactions.

---

### Article 13: Transparency and Provision of Information
> *"High-risk AI systems shall be designed and developed in such a way to ensure that their operation is sufficiently transparent to enable deployers to interpret the system's output and use it appropriately."*

#### GAS Technical Implementation:
- **Explicit GAA Wire Format:** The `GovernanceAuthorizationArtifact` transparently binds the exact action request to the policy decision, reason codes, expiration timestamp, and replay frame reference.
- **Standardized Machine-Readable Reason Codes:** In the event of a denial, GAS emits standardized reason codes (e.g., `action_not_allowed`, `required_field_missing`, `approval_quorum_not_met`, `request_too_large`) rather than opaque errors, enabling explainability and remediation.
- **Transport Audit Metadata:** Both HTTP APIs (`/audit`) and MCP responses (`to_mcp_content()`) attach verifiable GAA metadata directly to outputs, allowing downstream consumers to verify governance status.

---

### Article 14: Human Oversight (Human-in-the-Loop)
> *"High-risk AI systems shall be designed and developed in such a way... that they can be effectively overseen by natural persons during the period in which the AI system is in use... Oversight measures shall enable individuals to decide not to use the system or override its outputs."*

#### GAS Technical Implementation:
- **Cryptographic Approval Quorums (`SignedApproval`):** For critical or sensitive agent actions (e.g. initiating transactions, deploying code, modifying access controls), policies can mandate `required_approvals > 0`.
- **Detached Dual-Key Authorization:** Approvals can be generated out-of-band by human operators, security officers, or designated review systems using local Ed25519 signing keys.
- **Separation of Duties:** The delegating AI agent cannot forge or bypass human approvals; the `DeterministicArbiter` verifies the required number of unique, valid approver signatures in the trust store before issuing a GAA.

---

### Article 15: Accuracy, Robustness, and Cybersecurity
> *"High-risk AI systems shall be designed and developed in such a way that they achieve an appropriate level of accuracy, robustness, and cybersecurity... AI systems shall be resilient as regards errors, faults or inconsistencies... and resilient against attempts by unauthorized third parties to alter their use."*

#### GAS Technical Implementation:
- **At-Most-Once Execution (Anti-Replay):** Every GAA is bound to a single-use nonce claimed atomically in the database during execution barrier evaluation. Replayed, duplicated, or looping agent requests are rejected.
- **Strict Parsing & Canonical Serialization:** GAA wire formats and policies reject unexpected fields, non-integer timestamps, or malformed data structures, eliminating parser differential exploits.
- **Durable Key Revocation:** The `TrustStore` supports immediate and durable key revocation, instantly neutralizing compromised agent or approver identities.

---

## 2. Compliance Audit Checklist for Deployers

Organizations deploying autonomous AI agents under the EU AI Act can use the following GAS checklist for technical file preparation:

- [ ] **Policy Catalog:** Document all active `Policy` definitions, action whitelists, and required approvals.
- [ ] **Trust Store Configuration:** Maintain an inventory of all Ed25519 public key IDs (`issuer_key_id`, approvers, delegating agents) and verify that revocation procedures are documented.
- [ ] **Audit Log Persistence:** Ensure `SQLiteReplayLog` or database-backed replay logging is enabled with regular chain integrity audits (`verify_chain()`).
- [ ] **Quorum Thresholds:** Verify that high-risk actions (defined in Annex III) enforce `required_approvals >= 1` with designated human review procedures.
- [ ] **Periodic Audit Reports:** Export deterministic audit reports via `ReplayLog.audit_summary()` for compliance documentation.
