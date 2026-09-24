# Canonical Serialization

GAS hashes and signatures use deterministic UTF-8 JSON. CBOR is not used by this
implementation.

1. Objects use lexicographically sorted Unicode keys.
2. Arrays preserve semantic order.
3. JSON uses compact separators `,` and `:` with no whitespace.
4. Strings use UTF-8 with non-ASCII characters preserved.
5. Numbers are emitted by the JSON implementation without application-side coercion.
6. SHA-256 digests are lowercase hexadecimal.
7. CIDs are CIDv1, raw codec `0x55`, SHA-256 multihash `0x12 0x20`, lowercase base32 with `b` prefix.

UUID-bound replay hashing uses exactly the object fields `event`, `frame_id`,
`frame_uuid`, and `previous_hash`, sorted by the canonical encoder. The independent
implementation is [src/governed_autonomy/verify_replay.py](../src/governed_autonomy/verify_replay.py).
The published vector is [replay/tests/anchoring_vectors.json](../replay/tests/anchoring_vectors.json).