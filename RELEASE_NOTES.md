# Release Candidate Notes

## Security

- KMS/HSM signer boundary with rotation audit records and runtime signed attestations.
- Governance-admin registry quorum and execution-node signing/replay denial tests.
- Kubernetes separation and Prometheus alerts for replay, anchoring, and signing failures.

## Reproducibility

- GIR training recipes exist in `training/` and `gir/train/`.
- Redacted and synthetic manifests are included; licensed transformer weights are not vendored.
- Inference fixtures, canonical vectors, and independent replay verification are included.

## Patent support

- `PATENT_SUPPORT.md`, counsel memo, evidence collector, and release checklist are included.
- External legal review, KMS provisioning, and penetration testing remain release prerequisites.