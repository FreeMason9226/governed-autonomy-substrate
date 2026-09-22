```text
Network Working Group                                      GAS Working Group
Internet-Draft                                                    Draft-00
Intended status: Informational                                September 2026
Expires: March 2027

   The Governance Authorization Artifact (GAA) and Execution Barrier
                                Protocol
                         draft-gas-protocol-00

Abstract

   This document specifies the Governance Authorization Artifact (GAA)
   wire format and Execution Barrier protocol for autonomous artificial
   intelligence (AI) agents.  The protocol defines a cryptographically
   verifiable, append-only-audited authorization mechanism for actions
   with external side effects.  Before an agent action may execute, an
   authorized issuer produces a signed, expiring, nonce-bound GAA token.
   The execution barrier validates the token and atomically consumes its
   nonce, providing at-most-once execution semantics under concurrent or
   repeated delivery.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering Task
   Force (IETF).  Note that other groups may also distribute working
   documents as Internet-Drafts.  The list of current Internet-Drafts is
   at https://datatracker.ietf.org/drafts/current/.

Copyright Notice

   Copyright (c) 2026 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   2
   2.  Terminology . . . . . . . . . . . . . . . . . . . . . . . . .   2
   3.  Cryptographic Primitives  . . . . . . . . . . . . . . . . . .   3
   4.  Canonical JSON Encoding . . . . . . . . . . . . . . . . . . .   3
   5.  Governance Authorization Artifact (GAA) Wire Format . . . . .   4
       5.1.  Field Definitions . . . . . . . . . . . . . . . . . . .   4
       5.2.  Signature Payload . . . . . . . . . . . . . . . . . . .   5
   6.  Execution Barrier Processing Rules  . . . . . . . . . . . . .   5
   7.  Replay Log & Hash Chaining  . . . . . . . . . . . . . . . . .   6
   8.  Security Considerations . . . . . . . . . . . . . . . . . . .   7
   9.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .   8
   10. References  . . . . . . . . . . . . . . . . . . . . . . . . .   8

1.  Introduction

   Autonomous AI agents increasingly interact with enterprise data, APIs,
   and operational environments.  Existing application-layer protocols
   handle transport and communication (e.g., Model Context Protocol,
   Agent-to-Agent protocols) but lack a standardized, cryptographically
   auditable barrier for action authorization.

   The Governed Autonomy Substrate (GAS) protocol specifies:
   * A compact, canonical JSON wire format for authorization artifacts.
   * An atomic execution barrier enforcing at-most-once execution.
   * Append-only hash-chained logging for post-execution verification.

2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   * GAA: Governance Authorization Artifact.  A signed, expiring token
     authorizing a single action execution.
   * Execution Barrier: The enforcement boundary that validates the GAA
     and claims the nonce prior to invoking the action handler.
   * Replay Frame: A record in an append-only log containing an event,
     frame identifier, previous frame hash, and current frame hash.

3.  Cryptographic Primitives

   * Digital Signatures: Ed25519 (Edwards-curve Digital Signature
     Algorithm over Curve25519) as defined in [RFC8037].  Public keys
     are 32 raw bytes.  Signatures are 64 raw bytes.  All keys and
     signatures in JSON wire formats are encoded using unpadded URL-safe
     base64 ("base64url-nopad") per [RFC4648] Section 5.
   * Cryptographic Hash Function: SHA-256 [FIPS180-4].  Output digests
     are serialized as 64-character lowercase hexadecimal strings.
   * Nonces: Opaque strings containing at least 128 bits of entropy.

4.  Canonical JSON Encoding

   To ensure deterministic digital signatures and digests across
   heterogeneous environments, all signing payloads MUST be encoded
   using Canonical JSON:
   1. Object keys MUST be sorted lexicographically by Unicode code point.
   2. Whitespace between tokens MUST be omitted (no spaces after colons
      or commas).
   3. UTF-8 characters MUST NOT be escaped unless required by standard
      JSON syntax (e.g., control characters and double quotes).
   4. Floating point numbers SHOULD NOT be used in signed payloads;
      integers and fixed-precision strings MUST be used instead.

5.  Governance Authorization Artifact (GAA) Wire Format

   A GAA is represented as a JSON object containing exactly seven fields:

   {
     "action_request": { ... },
     "decision": { ... },
     "expires_at": 1790000000,
     "nonce": "n13EXzPGEZHNU-M4f2r4lLMmUK1DzJC5",
     "replay_frame_ref": "frame-001",
     "issuer_key_id": "issuer-alpha",
     "signature": "hQ...64-byte-base64url..."
   }

5.1.  Field Definitions

   * action_request (object, REQUIRED): The full request payload,
     including an "action" string identifier.
   * decision (object, REQUIRED): The policy decision object produced by
     an arbiter, containing an "allow" boolean and "allowed_actions".
   * expires_at (integer, REQUIRED): POSIX timestamp in seconds (UTC)
     specifying expiration.  Boolean values MUST be rejected.
   * nonce (string, REQUIRED): Unique, single-use token with >=128 bits
     entropy.
   * replay_frame_ref (string, REQUIRED): Identifier of the authorization
     replay frame recording GAA issuance.
   * issuer_key_id (string, REQUIRED): Key identifier of the signing key.
   * signature (string, REQUIRED): Ed25519 signature over the canonical
     unsigned payload.

5.2.  Signature Payload

   The bytes verified by the signature MUST be the Canonical JSON
   encoding of the GAA object with the "signature" key removed:

   {
     "action_request": <action_request>,
     "decision": <decision>,
     "expires_at": <expires_at>,
     "issuer_key_id": <issuer_key_id>,
     "nonce": <nonce>,
     "replay_frame_ref": <replay_frame_ref>
   }

6.  Execution Barrier Processing Rules

   Before invoking any action callable, the execution barrier MUST
   perform the following checks in order:

   1. Signature Verification: Verify GAA signature against the public
      key resolved from "issuer_key_id".  Reject if invalid or revoked.
   2. Expiration Check: Current wall-clock UTC time MUST be less than
      "expires_at".
   3. Frame Verification: A replay frame with ID "replay_frame_ref" MUST
      exist in the local log, and its request/decision payloads MUST
      match the GAA.
   4. Policy Verification: "decision.allow" MUST be true, and the action
      MUST be listed in "decision.allowed_actions".
   5. Atomic Nonce Claim: Atomically claim the nonce.  If the nonce has
      already been claimed, the barrier MUST reject the request
      immediately and MUST NOT invoke the action callable.

7.  Replay Log & Hash Chaining

   All authorization and execution events are committed to an append-only
   log formatted as JSON Lines (JSONL).  Each frame conforms to:

   {
     "event": { ... },
     "frame_hash": "<sha256-hex>",
     "frame_id": "<string>",
     "previous_hash": "<sha256-hex-or-empty>"
   }

   The genesis frame MUST set "previous_hash" to "".  Subsequent frames
   MUST set "previous_hash" to the "frame_hash" of the immediately
   preceding frame.  "frame_hash" is the SHA-256 hex digest of the
   Canonical JSON of {"event": ..., "frame_id": ..., "previous_hash": ...}.

8.  Security Considerations

   * Nonce Reuse: Reusing a nonce invalidates at-most-once execution.
     Nonce stores MUST be durable across restarts.
   * Clock Skew: Implementations SHOULD use synchronized wall-clock time
     (e.g., NTP) and MUST NOT accept client-supplied timestamps.
   * Fail-Closed Architecture: Any validation error, missing key, or
     broken hash link MUST cause execution to abort without side effects.

9.  IANA Considerations

   This document requests no immediate actions from IANA.  A future
   specification may register the MIME media type
   "application/vnd.gas.gaa+json".

10. References

   [RFC2119] Bradner, S., "Key words for use in RFCs to Indicate
             Requirement Levels", BCP 14, RFC 2119, March 1997.
   [RFC8037] Liusvaara, I., "CFRG Elliptic Curve Diffie-Hellman (ECDH)
             and Signatures in JSON Object Signing and Encryption",
             RFC 8037, January 2017.
   [RFC8174] Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
             2119 Key Words", BCP 14, RFC 8174, May 2017.
```
