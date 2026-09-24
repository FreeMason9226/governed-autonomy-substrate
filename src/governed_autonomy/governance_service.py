"""Capability-separated governance endpoints for signing and replay writes."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from .crypto import KeyPair, verify_signature
from .errors import AuthorizationError
from .replay import ReplayFrame, ReplayLog
from .signing import Signer


@dataclass(frozen=True)
class GovernanceAttestation:
    subject: str
    role: str
    operation: str
    evidence_digest: str
    nonce: str
    signer_key_id: str
    signature: str
    issued_at: int
    expires_at: int

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "subject": self.subject,
                "role": self.role,
                "operation": self.operation,
                "evidence_digest": self.evidence_digest,
                "nonce": self.nonce,
                "signer_key_id": self.signer_key_id,
                "issued_at": self.issued_at,
                "expires_at": self.expires_at,
            }
        )

    @classmethod
    def issue(
        cls,
        *,
        subject: str,
        role: str,
        operation: str,
        evidence: Any,
        nonce: str,
        signer: KeyPair,
        issued_at: int | None = None,
        ttl_seconds: int = 60,
    ) -> "GovernanceAttestation":
        issued_at = int(time.time()) if issued_at is None else issued_at
        if ttl_seconds <= 0:
            raise ValueError("attestation ttl must be positive")
        unsigned = cls(
            subject,
            role,
            operation,
            hashlib.sha256(canonical_json(evidence)).hexdigest(),
            nonce,
            signer.key_id,
            "",
            issued_at,
            issued_at + ttl_seconds,
        )
        return cls(
            subject=unsigned.subject,
            role=unsigned.role,
            operation=unsigned.operation,
            evidence_digest=unsigned.evidence_digest,
            nonce=unsigned.nonce,
            signer_key_id=unsigned.signer_key_id,
            signature=signer.sign(unsigned.unsigned_payload()),
            issued_at=unsigned.issued_at,
            expires_at=unsigned.expires_at,
        )

    def verify(self, public_key: Any, evidence: Any) -> bool:
        return self.evidence_digest == hashlib.sha256(canonical_json(evidence)).hexdigest() and verify_signature(
            public_key, self.unsigned_payload(), self.signature
        )


class GovernanceReplayWriter:
    """Write-only capability returned after governance ACL and attestation checks."""

    def __init__(self, service: "GovernanceService", subject: str, attestation: GovernanceAttestation):
        self._service = service
        self._subject = subject
        self._attestation = attestation

    def append(self, frame_id: str, event: dict[str, Any]) -> ReplayFrame:
        return self._service.append_execution(
            subject=self._subject,
            frame_id=frame_id,
            event=event,
            attestation=self._attestation,
        )


class GovernanceService:
    """Owns governance signing and replay writes behind role-bound attestations."""

    def __init__(
        self,
        *,
        signer: Signer,
        replay_log: ReplayLog,
        attestor: KeyPair | None = None,
        clock=None,
    ):
        self.signer = signer
        self.replay_log = replay_log
        self.attestor = attestor or signer
        self.clock = clock or (lambda: int(time.time()))
        self._used_attestations: set[tuple[str, str, str, str]] = set()

    def _authorize(
        self,
        *,
        subject: str,
        role: str,
        operation: str,
        evidence: Any,
        attestation: GovernanceAttestation,
    ) -> None:
        if attestation.subject != subject or attestation.role != role:
            raise AuthorizationError("governance attestation subject or role is invalid")
        token_id = (
            attestation.subject,
            attestation.operation,
            attestation.nonce,
            attestation.signature,
        )
        if attestation.operation != operation or not attestation.verify(self.attestor.public_key, evidence):
            raise AuthorizationError("governance attestation is invalid")
        now = self.clock()
        if now < attestation.issued_at or now >= attestation.expires_at:
            raise AuthorizationError("governance attestation is expired or not yet valid")
        if token_id in self._used_attestations:
            raise AuthorizationError("governance attestation has already been used")
        self._used_attestations.add(token_id)

    def sign_gaa(self, *, subject: str, payload: bytes, attestation: GovernanceAttestation) -> str:
        self._authorize(
            subject=subject,
            role="governance-signer",
            operation="issue-gaa",
            evidence=payload.decode("utf-8"),
            attestation=attestation,
        )
        if subject != self.signer.key_id:
            raise AuthorizationError("subject is not the configured governance signer")
        return self.signer.sign(payload)

    def append_replay(
        self,
        *,
        subject: str,
        frame_id: str,
        event: dict[str, Any],
        attestation: GovernanceAttestation,
    ) -> ReplayFrame:
        self._authorize(
            subject=subject,
            role="governance-writer",
            operation="append-replay",
            evidence={"frame_id": frame_id, "event": event},
            attestation=attestation,
        )
        return self.replay_log.append(frame_id, event)

    def execution_writer(
        self, *, subject: str, attestation: GovernanceAttestation
    ) -> GovernanceReplayWriter:
        self._authorize(
            subject=subject,
            role="execution-writer",
            operation="append-execution",
            evidence=subject,
            attestation=attestation,
        )
        return GovernanceReplayWriter(self, subject, attestation)

    def append_execution(
        self,
        *,
        subject: str,
        frame_id: str,
        event: dict[str, Any],
        attestation: GovernanceAttestation,
    ) -> ReplayFrame:
        self._authorize(
            subject=subject,
            role="execution-writer",
            operation="append-execution",
            evidence=subject,
            attestation=attestation,
        )
        if event.get("type") != "execution":
            raise AuthorizationError("execution capability may append execution events only")
        return self.replay_log.append(frame_id, event)

    def _internal_attestation(
        self, *, subject: str, role: str, operation: str, evidence: Any, nonce: str
    ) -> GovernanceAttestation:
        return GovernanceAttestation.issue(
            subject=subject,
            role=role,
            operation=operation,
            evidence=evidence,
            nonce=nonce,
            signer=self.attestor,
            issued_at=self.clock(),
        )