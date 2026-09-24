# Release Checklist

- [ ] Security review completed for KMS/HSM integration, attestation replay, ACLs, and network policy.
- [ ] External penetration test scheduled or completed; findings attached to the release record.
- [ ] Legal counsel reviewed `PATENT_SUPPORT.md` and approved claim-language mapping.
- [ ] GIR dataset license/provenance, manifest, seed, hyperparameters, and checkpoint hash/pointer recorded.
- [ ] GAA, replay, UUID, CID, and compact-ledger vectors independently verified.
- [ ] Key rotation executed in staging; old-key verification and audit trail checked.
- [ ] NORMAL, DEGRADED, SAFE, and RECOVERY transitions exercised.
- [ ] CI is green, including security/evidence gates, conformance, PostgreSQL integration, and Helm rendering.
- [ ] Test logs, coverage, CI run URL, manifests, vectors, and review sign-offs bundled for counsel/examiner.