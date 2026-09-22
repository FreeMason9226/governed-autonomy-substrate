"""
Conformance test suite — validates the Python reference implementation against
the language-agnostic test vectors in tests/conformance/vectors/.

These test vector files serve as the source of truth for all implementations:
- SPEC.md §3 Canonical JSON: canonical_json.json
- SPEC.md §4 Governance Authorization Artifact (GAA): gaa.json
- SPEC.md §5 Signed Approval: signed_approval.json
- SPEC.md §6 Policy Definition & Digest: policy_digest.json
- SPEC.md §8 Replay Frame Hash Chaining: replay_chain.json
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from governed_autonomy.canonical import b64decode, canonical_json
from governed_autonomy.crypto import verify_signature
from governed_autonomy.models import GovernanceAuthorizationArtifact, SignedApproval
from governed_autonomy.policy import Policy, policy_from_dict
from governed_autonomy.replay import ReplayFrame, ReplayLog

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load_json(filename: str) -> dict[str, Any]:
    path = VECTORS_DIR / filename
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# §3 Canonical JSON
# ---------------------------------------------------------------------------


class TestCanonicalJson:
    """SPEC.md §3 — Canonical JSON encoding."""

    @pytest.mark.parametrize(
        "vec",
        _load_json("canonical_json.json")["vectors"],
        ids=lambda v: v["id"],
    )
    def test_canonical_encoding(self, vec: dict[str, Any]) -> None:
        result = canonical_json(vec["input"])

        if "expected_hex" in vec:
            assert result.hex() == vec["expected_hex"], (
                f"[{vec['id']}] {vec['description']}\n"
                f"  got:      {result.hex()}\n"
                f"  expected: {vec['expected_hex']}"
            )

        if "expected_utf8" in vec:
            assert result.decode("utf-8") == vec["expected_utf8"], (
                f"[{vec['id']}] {vec['description']}\n"
                f"  got:      {result.decode('utf-8')!r}\n"
                f"  expected: {vec['expected_utf8']!r}"
            )


# ---------------------------------------------------------------------------
# §4 GAA Wire Format & Signature Conformance
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def gaa_suite() -> dict[str, Any]:
    return _load_json("gaa.json")


@pytest.fixture(scope="module")
def gaa_public_key(gaa_suite: dict[str, Any]) -> Ed25519PublicKey:
    pub_bytes = b64decode(gaa_suite["test_key"]["public_key_b64url"])
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


class TestGAAConformance:
    """SPEC.md §4 — GAA wire format parsing, serialization, and signature verification."""

    def test_valid_gaa_vectors(
        self, gaa_suite: dict[str, Any], gaa_public_key: Ed25519PublicKey
    ) -> None:
        for vec in gaa_suite["valid_vectors"]:
            gaa_dict = vec["gaa"]
            gaa = GovernanceAuthorizationArtifact.from_dict(gaa_dict)

            # 1. Check canonical unsigned payload serialization
            unsigned_bytes = gaa.unsigned_payload()
            assert unsigned_bytes.decode("utf-8") == vec["expected_unsigned_canonical_utf8"]
            assert (
                hashlib.sha256(unsigned_bytes).hexdigest()
                == vec["expected_unsigned_canonical_sha256"]
            )

            # 2. Check signature verification
            assert verify_signature(gaa_public_key, unsigned_bytes, gaa.signature) is True

            # 3. Check round-trip preservation
            assert gaa.to_dict() == gaa_dict

    def test_invalid_gaa_vectors(
        self, gaa_suite: dict[str, Any], gaa_public_key: Ed25519PublicKey
    ) -> None:
        for vec in gaa_suite["invalid_vectors"]:
            gaa_dict = vec["gaa"]
            expected_err = vec["expected_error"]

            if expected_err == "invalid_signature":
                gaa = GovernanceAuthorizationArtifact.from_dict(gaa_dict)
                assert (
                    verify_signature(gaa_public_key, gaa.unsigned_payload(), gaa.signature)
                    is False
                )
            else:
                with pytest.raises(ValueError):
                    GovernanceAuthorizationArtifact.from_dict(gaa_dict)


# ---------------------------------------------------------------------------
# §5 SignedApproval Conformance
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def approval_suite() -> dict[str, Any]:
    return _load_json("signed_approval.json")


@pytest.fixture(scope="module")
def approval_public_key(approval_suite: dict[str, Any]) -> Ed25519PublicKey:
    pub_bytes = b64decode(approval_suite["test_key"]["public_key_b64url"])
    return Ed25519PublicKey.from_public_bytes(pub_bytes)


class TestSignedApprovalConformance:
    """SPEC.md §5 — SignedApproval wire format and request binding."""

    def test_valid_approval_vectors(
        self, approval_suite: dict[str, Any], approval_public_key: Ed25519PublicKey
    ) -> None:
        for vec in approval_suite["valid_vectors"]:
            appr_dict = vec["approval"]
            approval = SignedApproval.from_dict(appr_dict)

            # 1. Check canonical unsigned payload serialization
            unsigned_bytes = approval.unsigned_payload()
            assert unsigned_bytes.decode("utf-8") == vec["expected_unsigned_canonical_utf8"]

            # 2. Check signature verification
            assert approval.verify(approval_public_key) is True

            # 3. Check round-trip serialization
            assert approval.to_dict() == appr_dict

    def test_request_binding_digest(self, approval_suite: dict[str, Any]) -> None:
        for vec in approval_suite["request_binding_vectors"]:
            raw_req = vec["raw_request"]
            # SPEC §5.3: strip 'approvals' key before hashing
            stripped = {k: v for k, v in raw_req.items() if k != "approvals"}
            assert stripped == vec["expected_stripped_request"]
            encoded = canonical_json(stripped)
            assert encoded.decode("utf-8") == vec["expected_canonical_utf8"]
            digest = hashlib.sha256(encoded).hexdigest()
            assert digest == vec["expected_request_digest"]


# ---------------------------------------------------------------------------
# §6 Policy Digest Stability
# ---------------------------------------------------------------------------


class TestPolicyDigestConformance:
    """SPEC.md §6.3 — Policy digest MUST be deterministic and stable across implementations."""

    @pytest.mark.parametrize(
        "vec",
        _load_json("policy_digest.json")["vectors"],
        ids=lambda v: v["id"],
    )
    def test_policy_digest_vectors(self, vec: dict[str, Any]) -> None:
        policy_dict = vec["policy"]
        policy = policy_from_dict(policy_dict)

        # 1. Canonical serialization of policy dictionary
        canonical_bytes = canonical_json(policy.to_dict())
        assert canonical_bytes.decode("utf-8") == vec["expected_canonical_utf8"]

        # 2. SHA-256 digest match
        computed_digest = policy.digest()
        assert computed_digest == vec["expected_digest"]


# ---------------------------------------------------------------------------
# §8 Replay Frame Hash Chaining Conformance
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def replay_suite() -> dict[str, Any]:
    return _load_json("replay_chain.json")


class TestReplayChainConformance:
    """SPEC.md §8 — Hash chain calculation and chain validation."""

    def test_chain_vectors(self, replay_suite: dict[str, Any]) -> None:
        previous_hash = ""
        for vec in replay_suite["chain_vectors"]:
            frame = ReplayFrame.create(vec["frame_id"], vec["previous_hash"], vec["event"])

            # Verify previous_hash link
            assert frame.previous_hash == previous_hash

            # Verify canonical encoding and frame_hash
            body = {
                "event": vec["event"],
                "frame_id": vec["frame_id"],
                "previous_hash": vec["previous_hash"],
            }
            assert canonical_json(body).decode("utf-8") == vec["expected_canonical_body_utf8"]
            assert frame.frame_hash == vec["expected_frame_hash"]

            previous_hash = frame.frame_hash

    def test_chain_corruption_detection(self, replay_suite: dict[str, Any]) -> None:
        for vec in replay_suite["corruption_vectors"]:
            log = ReplayLog()
            # Manually inject frames into log internal list to simulate reading external data
            for f in vec["frames"]:
                frame = ReplayFrame(
                    frame_id=f["frame_id"],
                    previous_hash=f["previous_hash"],
                    event=f["event"],
                    frame_hash=f["frame_hash"],
                )
                log._frames.append(frame)

            # Must fail validation
            assert log.verify_chain() is vec["expected_valid"]
