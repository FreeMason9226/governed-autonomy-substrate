# External Security Review Request

**Status:** preparation, not completed.  
**Target:** independent assessor with cloud KMS/HSM and Kubernetes expertise.  
**Focus:** key separation, replay immutability, signed service attestation, registry ACL/quorum,
UUID/CID anchoring, rotation audit integrity, and resilience-mode fail-closed behavior.

The assessor should execute the scope in [docs/security-review.md](docs/security-review.md),
review `deploy/governance-separation.yaml`, and attach a dated report with findings,
reproduction steps, severity, remediation status, and retest evidence. Production release
requires the report and legal/security sign-off to be attached to the checklist.