# External Security Review Request

**Status:** preparation; engagement not completed in this repository.
**Target:** independent assessor with cloud KMS/HSM and Kubernetes expertise.  
**Focus:** key separation, replay immutability, signed service attestation, registry ACL/quorum,
UUID/CID anchoring, rotation audit integrity, and resilience-mode fail-closed behavior.

The assessor should execute the scope in [docs/security-review.md](docs/security-review.md),
review `deploy/governance-separation.yaml`, and attach a dated report with findings,
reproduction steps, severity, remediation status, and retest evidence. Production release
requires the report and legal/security sign-off to be attached to the checklist.

**Scheduling action:** assign an independent assessor, agree scope and test window, and
record the engagement letter/report identifier in `RELEASE_CHECKLIST.md` before release.