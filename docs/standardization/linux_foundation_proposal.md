# Linux Foundation AI & Data Project Proposal

## 1. Project Identification

- **Project Name:** Governed Autonomy Substrate (GAS)
- **Proposed Project Stage:** Incubation
- **Sponsoring Foundation:** Linux Foundation AI & Data (LF AI & Data)
- **License:** Apache License 2.0
- **Source Repository:** [https://github.com/governed-autonomy/governed-autonomy-substrate](https://github.com/governed-autonomy/governed-autonomy-substrate)
- **Primary Contacts / Initial Maintainers:**
  - Project Leads & Protocol Authors (GAS Project Technical Steering Committee)

---

## 2. Executive Summary & Mission

### Problem Statement
The rapid deployment of autonomous AI agents across enterprise and industrial software has introduced a critical security and compliance gap: **the absence of a standardized, verifiable execution barrier for agent actions with side effects**. While connection protocols (such as MCP) establish client-server communication and agent protocols (such as Google A2A) handle task routing, the authorization boundary *between* an LLM's intent and an external action remains largely ad-hoc, in-memory, and unauditable.

### Mission
The mission of the **Governed Autonomy Substrate (GAS)** project is to establish an open, vendor-neutral, cryptographically verifiable action execution barrier standard for all autonomous AI agents. GAS ensures that no agent action with real-world side effects may execute without:
1. A deterministic evaluation against an organization's active policy.
2. A cryptographically signed, expiring token bound to a single-use nonce: the **Governance Authorization Artifact (GAA)**.
3. Atomic nonce consumption enforcing **at-most-once execution** under concurrent delivery.
4. Permanent commitment of authorization and execution decisions to an append-only, hash-chained audit log.

---

## 3. Alignment with LF AI & Data

The GAS project strongly aligns with the LF AI & Data mission to build sustainable open source AI ecosystems:
- **Complementary to Existing Projects:** GAS complements existing LF AI & Data and broader agent projects:
  - **A2A (Agent-to-Agent Protocol):** GAS provides the execution barrier and delegation verification primitives for A2A task hand-offs.
  - **Open Data & AI Governance:** Directly implements technical controls mandated by international AI governance standards (NIST AI RMF, EU AI Act Articles 9, 12, 13, 14).
  - **Interoperability Across Runtimes:** Provides language-agnostic conformance test vectors enabling native implementations in Python, Go, Rust, TypeScript, and Java.

---

## 4. Technical Maturity & Current Status

The project is technically mature and ready for community incubation:
- **Formal Specification:** Complete language-agnostic specification published in [`SPEC.md`](../../SPEC.md) (18 formal sections covering wire formats, canonical JSON rules, Ed25519 cryptographic profiles, replay frames, and barrier invariants).
- **Executable Conformance Suite:** 5 language-agnostic JSON vector test suites (`canonical_json.json`, `gaa.json`, `signed_approval.json`, `policy_digest.json`, `replay_chain.json`) passing 100% against the reference runner.
- **Reference Implementation:** Production-grade Python reference library with 123 automated tests passing, strict type checking, and zero mandatory external dependencies beyond `cryptography`.
- **Ecosystem Adapters:**
  - Model Context Protocol (MCP) Gateway adapter.
  - LangChain & LangGraph execution barrier tools and callback handlers.
  - Google A2A protocol task delegation guard.

---

## 5. Governance Model & Technical Steering Committee (TSC)

### 5.1 Technical Steering Committee (TSC)
The project will be governed by a Technical Steering Committee (TSC) operating under open-governance principles:
- **Composition:** Initial TSC comprised of core maintainers from implementing organizations, with voting seats allocated according to ongoing contributions.
- **Decision Making:** Consensus-seeking model with fallback to majority vote for technical determinations.
- **RFC Process:** Any changes to protocol wire formats, cryptographic primitives, or barrier invariants require an open Request for Comments (RFC) according to [`CONTRIBUTING.md`](../../CONTRIBUTING.md) and [`docs/rfc/template.md`](../rfc/template.md).

### 5.2 Release & Maintenance Policy
- **Semantic Versioning:** Strict adherence to SemVer 2.0. The Protocol Version and Implementation Version are tracked independently in [`CHANGELOG.md`](../../CHANGELOG.md).
- **Backward Compatibility:** Wire format modifications must preserve backward compatibility or be introduced through a new protocol version with an RFC.

---

## 6. Project Roadmap Under LF AI & Data

1. **Phase 1 (Months 1–6): Multi-Language Reference SDKs**
   - Release official reference SDKs in Go and TypeScript/JavaScript validated against the conformance suite.
   - Establish weekly public working group meetings under LF AI & Data auspices.
2. **Phase 2 (Months 6–12): Standard Working Group Collaboration**
   - Collaborate with NIST AI Agent Standards Initiative working groups.
   - Form an interoperability group with enterprise MCP server developers and agent framework maintainers.
3. **Phase 3 (Months 12–24): Formal Standards Submission**
   - Advance the GAA wire format onto the IETF Informational RFC track.
   - Graduate from LF AI & Data Incubation to Graduated Project status.

---

## 7. Intellectual Property & Infrastructure

- **License:** Apache License, Version 2.0.
- **Contributor Agreement:** Developer Certificate of Origin (DCO) enforced on all pull requests via DCO bot.
- **Trademarks:** The "Governed Autonomy Substrate" and "GAS" marks to be transferred to the Linux Foundation upon acceptance.
