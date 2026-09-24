# GAA and Replay-Frame Canonical Format

This document is the compact implementation-facing format contract. The normative
wire details remain in [SPEC.md](../SPEC.md); this page records the UUID and ledger
extensions used by the evidence tests.

## Canonical serialization

Every signed or hashed object is UTF-8 JSON with lexicographically sorted object keys,
compact separators, and `ensure_ascii=false`. SHA-256 digests are lowercase hexadecimal.
Ed25519 signatures are base64url without padding.

## GAA

The exact fields are `action_request`, `decision`, `expires_at`, `nonce`,
`replay_frame_ref`, `issuer_key_id`, and `signature`. The signature covers the first six
fields in canonical JSON order. A GAA is rejected when its signature, expiry, nonce,
authorization frame, policy decision, or allowed action does not verify.

## Replay frame

The implementation frame fields are `frame_id`, `previous_hash`, `event`, and `frame_hash`.
For externally anchored evidence, `frame_uuid` is included in the hashed body:

```json
{"event":{"nonce":"n-1","type":"authorization"},"frame_id":"frame-1","frame_uuid":"00000000-0000-0000-0000-000000000001","previous_hash":""}
```

`frame_hash = SHA256(canonical_json(body))`. The CID is CIDv1 using the raw codec (`0x55`)
and SHA-256 multihash (`0x12 0x20`), encoded as lowercase base32 with a `b` prefix.
The full vector and independent verification instructions are in
[docs/cryptographic_vectors.json](cryptographic_vectors.json).

## Compact ledger record

An on-chain record stores `frame_uuid`, `frame_cid`, `frame_hash`,
`arbiter_selection_digest`, and the previous record reference. The off-chain frame is
accepted only when its recomputed CID and arbiter selection digest match this record.