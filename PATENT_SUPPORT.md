# Patent-Support Evidence Map

This is a technical traceability memo, not legal advice or an assertion of patentability.
Counsel should map the implementation to the controlling claim language and preserve the
commit, CI run, and environment metadata for every cited result.

| Evidence area | Implementation | Automated evidence |
| --- | --- | --- |
| GAA issuance and verification | `issuer.py`, `models.py`, `engine.py` | `tests/test_governance_bottleneck_e2e.py`, conformance vectors |
| Governance bottleneck / execution barrier | `engine.py` | GAA-required execution test |
| Replay buffer and integrity chain | `replay.py`, `storage.py` | replay recovery and integrity tests |
| Arbiter selection and policy constraints | `policy.py`, `mesh.py` | policy, mesh, and registry tests |
| GIR synthesis and training provenance | `governance.py`, `training/` | manifest, redacted fixtures, training recipe |
| Claim 51A confidence metric | `claim51a.py` | `tests/test_anchoring_claim51a.py` |
| UUID hashing and ledger anchoring | `anchoring.py` | vector, CID, compact-record tests |
| Key separation and attestations | `governance_service.py`, `signing.py` | denial, KMS, rotation tests |
| Registry immutability and quorum | `policy.py`, `platform_admin.py` | `tests/test_registry_acl.py` |
| Independent verifier and evidence packaging | `scripts/verify_anchor.py`, `scripts/collect_evidence.py`, `evidence/` | generated review bundle |

## Second-examination fix mapping

1. Key separation is addressed by the KMS/HSM signer boundary and deployment manifests.
2. Reproducibility is addressed by the GIR manifest, pinned dependencies, redacted data,
   deterministic seed, and checkpoint publication procedure.
3. Cryptographic anchoring is addressed by the canonical format, vectors, CID rules, and
   independent verifier tests.
4. Claim 51A is addressed by the exact `Cpred` implementation and known distributions.
5. Operational enforceability is addressed by signed attestations, registry quorum,
   resilience modes, telemetry, and CI gates.

## Counsel memo

The implementation evidence supports a technical narrative in which a governance layer
arbitrates a request, binds the decision into a signed GAA, records the authorization in
an append-only replay chain, and permits execution only after independent verification.
The GIR artifacts support provenance and reproducibility for obligation extraction, while
the scoring module implements the stated entropy normalization. UUID-bound hashes and CID
records provide an independently recomputable integrity anchor. KMS/HSM adapters, signed
identity attestations, policy-admin quorum, and fail-closed resilience modes address the
second-examination fixes as engineering controls. These artifacts demonstrate implementation
and test coverage only; counsel must determine claim scope, written-description support,
enablement, and legal significance for Claim 1A, Claim 51A, Section 5.4A, Section 5.7,
and Section 5.4A from the governing prosecution record.