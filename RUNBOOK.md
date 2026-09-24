# Operational Runbook

## Divergence or anchoring failure

Move the system to `SAFE`, stop new issuance, revoke affected identities, preserve KMS
audit records, and run `python scripts/verify_anchor.py`. Compare every off-chain frame
with its compact ledger record; never repair a divergent log in place.

## Unauthorized signing or replay write

Block the execution namespace, revoke the caller token, rotate the KMS key, inspect the
immutable key audit log, and attach the failed request and attestation digest to the
incident evidence bundle.

## Recovery

Restore only the last verified replay snapshot, run the full CI security gate, obtain
two-person approval, and transition `SAFE -> RECOVERY -> NORMAL`. Use
[docs/incident-runbook.md](docs/incident-runbook.md) for the detailed procedure.