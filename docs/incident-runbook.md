# Integrity and Attestation Incident Runbook

## Containment

1. Move the resilience controller to `SAFE`; stop authorization issuance and external side effects.
2. Revoke the affected service identity and KMS key version; block the execution namespace from governance egress.
3. Preserve immutable KMS audit records, attestation tokens, replay storage, ledger records, and deployment manifests.

## Verification

1. Run `python scripts/verify_anchor.py docs/cryptographic_vectors.json`.
2. Load the replay log with its recovery verifier and record the first broken frame, previous hash, and CID.
3. Recompute every affected UUID-bound frame hash and compare it with the compact ledger record.
4. Check KMS signing and rotation audit entries for unauthorized subjects, stale keys, or duplicate attestation nonces.

## Recovery

1. Rotate to a new KMS/HSM key version and publish its public key through the trusted registry.
2. Restore replay data only from the last verified snapshot; never overwrite a divergent log in place.
3. Run the security/evidence CI gate and the conformance suite.
4. Transition `SAFE -> RECOVERY -> NORMAL` only after two-person approval and an independent verification record.

## Remediation

Attach the incident timeline, hashes, KMS audit export, affected identities, CI run, operator approvals,
and external review findings to the release evidence bundle. Do not rely on a local test result as proof
that a production ledger or KMS was uncompromised.