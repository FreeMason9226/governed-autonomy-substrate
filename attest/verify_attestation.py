"""Verify a pull-request attestation signature and required fields."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from attest.common import load_public_key, verify_attestation


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attest", required=True, help="signed attestation JSON")
    parser.add_argument("--pubkey", required=True, help="trusted PEM-encoded RSA or ECDSA public key")
    args = parser.parse_args(argv)

    try:
        with open(args.attest, encoding="utf-8") as attestation_file:
            attestation: Any = json.load(attestation_file)
        public_key = load_public_key(args.pubkey)
        valid = verify_attestation(attestation, public_key)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"Attestation verification failed: {exc}", file=sys.stderr)
        return 1
    if not valid:
        print("Attestation verification failed: invalid signature", file=sys.stderr)
        return 1
    print("Attestation signature and required fields verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
