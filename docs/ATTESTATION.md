# PR Attestation and Audit

## Overview and threat model

This demo signs a JSON record binding a pull request, actor, approver, policy
decision, risk score, rationale, timestamp, and commit SHA. The signature is
made over the JSON object without its `signature` field, using sorted keys and
compact separators. RSA keys use RSA-PSS with SHA-256; ECDSA keys use
ECDSA-SHA-256. Verification requires a separately trusted public key.

The signature detects modification and proves that the holder of the matching
private key signed the payload. It does not prove that the named approver
actually approved the change, that the policy evaluation was correct, or that
the system clock is authoritative. The included GitHub Actions workflow uses
mock policy data and a simulated approver; it is an integration example, not a
production approval gate. Anyone who can read the repository can use the
committed demo private key, so its signatures are explicitly untrusted.

## Usage

Install the project (which includes the `cryptography` dependency), then run:

```sh
./scripts/attest.sh generate \
  --pr 123 \
  --actor ai-bot \
  --approver alice@example.com \
  --commit abcdef123 \
  --key attest/demo_key.pem \
  --policy-id policy-001 \
  --risk-score 8 \
  --rationale "Policy checks passed" \
  --out attest/output.json

./scripts/attest.sh verify --attest attest/output.json --pubkey attest/demo_key.pub
```

`generate` writes and verifies the signed JSON, then appends one compact JSON
object per line to `audit/ledger.jsonl`. It stops without appending if
generation or verification fails. `AUDIT_LEDGER` may be set to choose another
ledger path. `verify` returns zero only when required fields and the signature
are valid. The default key and output paths for `generate` are
`attest/demo_key.pem` and `attest/output.json`.

## Python utility API and CLI

`attest/generate_attestation.py` accepts `--pr`, `--actor`, `--approver`,
`--policy-id`, `--risk-score`, `--rationale`, `--commit`, `--key`, and `--out`.
It creates an ISO-8601 UTC timestamp. The module's
`build_attestation(..., private_key, timestamp=None)` function builds and signs
the same record, and is useful to callers that already manage key objects.

`attest/verify_attestation.py` accepts `--attest` and `--pubkey`. Its
`verify_attestation(attestation, public_key)` helper raises `ValueError` for a
malformed or incomplete record and returns `False` for a cryptographically
invalid signature. `attest.common.canonicalize(payload)` returns the UTF-8
canonical JSON bytes used by both signing and verification. The signed JSON
includes a base64-encoded `signature` value, excluded from the signed payload.

The workflow is defined in `.github/workflows/attest.yml`, where GitHub Actions
discovers workflows, and mirrored at `ci/attest.yml` to keep the requested CI
configuration alongside the project's other CI materials. It uploads both
the attestation and generated ledger as workflow artifacts; it does not push
changes to the pull request branch.

## Security considerations

- `attest/demo_key.pem` is a public demo/test key, not a credential. Never use
  it or commit production private keys. Store production signing keys in an
  HSM/KMS or protected secret store and make the workflow obtain signatures
  through a narrowly scoped signer.
- The verifier's public key must be provisioned through a trusted channel.
  Accepting a public key supplied alongside an untrusted attestation does not
  establish signer identity.
- Use an authoritative timestamp service such as RFC 3161 when trusted signing
  time is required. This demo records the local system clock.
- `audit/ledger.jsonl` is append-only by convention and uses a file lock for
  concurrent local writes, but is not tamper-proof: a local administrator can
  edit or replace it. The workflow uploads an artifact and does not commit the
  ledger. Production systems should use immutable/WORM object storage, a
  separately administered append-only log, or a verifiable transparency log,
  with retention, access controls, and independent monitoring.
- Review mock policy results and approver identity before using this design as
  a real authorization control.

## Key rotation and revocation

1. Generate a new private/public key pair in the approved key-management
   service; do not generate or store production private keys in this repository.
2. Distribute the new public key through the trusted verifier configuration,
   recording its key identifier and activation time. During a controlled
   migration, verification may accept both old and new trusted public keys.
3. Switch the signer to the new key and issue a test attestation. Verify it
   using the deployed verifier before retiring the old key.
4. For compromise, immediately disable the old signing key, remove it from the
   trusted-key set, and record its key identifier, compromise window, and
   affected attestations in the audit system. Revoke or reissue affected
   attestations after review; historical signatures should not be silently
   rewritten.
5. Retain old public keys and rotation/revocation records as required to
   validate unaffected historical attestations.
