"""Sign and verify demo GAA (Governed Autonomy Attestation) records, and keep a hash-chained audit log."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNING_KEY_ENV = "GAA_DEMO_SIGNING_KEY"  # base64 of a 32-byte Ed25519 seed (live mode only)
# Public, well-known seed: simulation records are NOT trustworthy and are marked simulated.
SIMULATION_SEED = hashlib.sha256(b"gaa-demo-simulation-key-not-secret").digest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def load_private_key(simulated: bool) -> Ed25519PrivateKey:
    if simulated:
        return Ed25519PrivateKey.from_private_bytes(SIMULATION_SEED)
    raw = os.environ.get(SIGNING_KEY_ENV)
    if not raw:
        raise SystemExit(f"{SIGNING_KEY_ENV} is required for live signing")
    try:
        seed = base64.b64decode(raw, validate=True)
        return Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError:
        raise SystemExit(f"{SIGNING_KEY_ENV} must be base64 of a 32-byte Ed25519 seed") from None


def public_key_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign_gaa(claims: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    return {
        "claims": claims,
        "public_key": public_key_b64(key),
        "signature": base64.b64encode(key.sign(canonical(claims))).decode(),
    }


def verify_gaa(gaa: dict[str, Any], trusted_public_key: str | None = None) -> bool:
    """Verify the signature; if trusted_public_key is given, it must also match the embedded key."""
    try:
        if trusted_public_key is not None and gaa["public_key"] != trusted_public_key:
            return False
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(gaa["public_key"], validate=True))
        public.verify(base64.b64decode(gaa["signature"], validate=True), canonical(gaa["claims"]))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False


def build_claims(policy_result: dict[str, Any], approver: str, simulated: bool, issued_at: str) -> dict[str, Any]:
    return {
        "type": "gaa-demo/v1",
        "pr_number": policy_result["pr_number"],
        "head_sha": policy_result["head_sha"],
        "policy_input_digest": policy_result["input_digest"],
        "policy_status": policy_result["status"],
        "approved_by": approver,
        "approval_simulated": simulated,
        "issued_at": issued_at,
    }


class AuditLog:
    """Append-only, hash-chained list of events (immutable-style: tampering breaks the chain)."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    def append(self, event: str, timestamp: str, data: dict[str, Any]) -> dict[str, Any]:
        prev = self.records[-1]["hash"] if self.records else "0" * 64
        body = {"seq": len(self.records), "event": event, "timestamp": timestamp, "data": data, "prev_hash": prev}
        record = {**body, "hash": hashlib.sha256(canonical(body)).hexdigest()}
        self.records.append(record)
        return record

    @staticmethod
    def verify(records: list[dict[str, Any]]) -> bool:
        prev = "0" * 64
        for index, record in enumerate(records):
            body = {k: v for k, v in record.items() if k != "hash"}
            if record.get("seq") != index or body.get("prev_hash") != prev:
                return False
            if hashlib.sha256(canonical(body)).hexdigest() != record.get("hash"):
                return False
            prev = record["hash"]
        return True


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Sign or verify a demo GAA / audit record")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sign = sub.add_parser("sign", help="sign a GAA from a policy result")
    sign.add_argument("--policy-result", required=True)
    sign.add_argument("--approver", required=True, help="login of the human who approved")
    sign.add_argument("--issued-at", required=True, help="ISO-8601 timestamp")
    sign.add_argument("--live", action=argparse.BooleanOptionalAction, default=False,
                      help=f"use {SIGNING_KEY_ENV} and mark the approval as real (default: simulation key)")
    sign.add_argument("--output", required=True)
    ver = sub.add_parser("verify", help="verify a GAA file (exit 0 valid, 1 invalid)")
    ver.add_argument("gaa")
    ver.add_argument("--trusted-public-key", help="base64 public key the signer must match")
    aud = sub.add_parser("verify-audit", help="verify an audit JSON file's hash chain")
    aud.add_argument("audit")
    args = parser.parse_args(argv)

    if args.cmd == "sign":
        with open(args.policy_result, encoding="utf-8") as handle:
            result = json.load(handle)
        key = load_private_key(simulated=not args.live)
        claims = build_claims(result, args.approver, not args.live, args.issued_at)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(sign_gaa(claims, key), handle, indent=2, sort_keys=True)
            handle.write("\n")
        return 0
    with open(args.gaa if args.cmd == "verify" else args.audit, encoding="utf-8") as handle:
        data = json.load(handle)
    ok = verify_gaa(data, args.trusted_public_key) if args.cmd == "verify" else AuditLog.verify(data["records"])
    sys.stdout.write("valid\n" if ok else "INVALID\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
