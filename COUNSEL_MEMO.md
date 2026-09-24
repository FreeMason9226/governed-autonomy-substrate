# Counsel Handoff Memo

## Purpose

This memo maps the five Second-Examination engineering fixes to reproducible repository
artifacts. It is technical evidence, not legal advice or a conclusion on claim scope,
written description, enablement, novelty, or non-obviousness.

## 1. Key separation and enforceability

Production composition uses `KMSHSMBackedSigner` in
`src/governed_autonomy/signing.py`; `bootstrap.py` requires a remote KMS endpoint and
public key instead of a private issuer key. Signed, expiring, single-use service
attestations are enforced by `governance_service.py`. Registry changes require signed
multi-party approvals in `policy.py` and `platform_admin.py`. Evidence is in
`tests/test_kms_signing.py`, `tests/test_governance_service.py`, and
`tests/test_registry_acl.py`. Kubernetes separation is declarative in
`deploy/governance-separation.yaml` and the Helm deployment contains no private-key
injection. Actual KMS provisioning and external review remain deployment evidence.

## 2. GIR reproducibility

`training/train_gir.py` and `gir/train/train.py` define the deterministic recipe,
preprocessing, seed, hyperparameters, redacted/synthetic manifests, and checkpoint
references. `tests/test_gir_inference.py` and `tests/test_gir_provenance.py` provide
canonical inference and metadata-hash checks. The published hash is for smoke metadata;
the licensed transformer weights must be separately published and hashed before legal
submission.

## 3. Cryptographic anchoring

`docs/CANONICAL_SERIALIZATION.md`, `replay/tests/anchoring_vectors.json`,
`src/governed_autonomy/anchoring.py`, and `src/governed_autonomy/verify_replay.py`
define and independently recompute UUID-bound SHA-256 hashes, CIDv1 values, compact
ledger records, and arbiter-selection proofs. `tests/test_verify_replay.py` and
`tests/test_anchoring_claim51a.py` verify the vector. The independent CLI produces
`replay verification: OK`.

## 4. Claim 51A scoring

`src/governed_autonomy/claim51a.py` implements
`Cpred = 1 - H(Ppred) / log2(|D|)`, with deterministic validation. Known deterministic,
uniform, and intermediate distributions are tested in `tests/test_anchoring_claim51a.py`.
Counsel should compare this implementation to the prosecution-approved formula.

## 5. Operational proof and release evidence

`tests/test_governance_bottleneck_e2e.py` proves that execution without a GAA fails and
valid execution succeeds. `resilience.py`, `tests/test_resilience_observability.py`,
`deploy/observability/`, `RUNBOOK.md`, and `docs/incident-runbook.md` cover containment,
monitoring, and recovery. `scripts/collect_evidence.py` and
`scripts/build_evidence_archive.py` produce the dated local package. CI runs the full
test suite and focused security/evidence gates through `.github/workflows/ci.yml`.
The browser review context is preserved in `tools/browser_context.json` and included in
the counsel archive for traceability only.

## Reproduction

```powershell
$env:PYTHONPATH='src'
python -m pytest
python scripts/split_anchor_vector.py
python -m governed_autonomy.verify_replay --record evidence/anchor-sample/record.json --frame evidence/anchor-sample/frame.json --selection evidence/anchor-sample/selection.json
python scripts/build_evidence_archive.py
```