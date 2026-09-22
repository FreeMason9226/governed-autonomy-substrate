"""
Google Agent-to-Agent (A2A) Protocol Integration — Governed Task Delegation.

This module implements cryptographically verified, policy-governed task hand-offs
between autonomous AI agents. When Agent A delegates an action to Agent B:
1. Agent A binds the task to an authorized GAA token.
2. Agent A signs an ``A2ATaskDelegation`` artifact targeted at Agent B.
3. Agent B's ``A2AGuard`` validates the delegator signature, checks recipient
   targeting, executes through the GAS execution barrier, claims the GAA nonce,
   and writes the execution event to the replay log.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_json
from .crypto import KeyPair, verify_signature
from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .models import GovernanceAuthorizationArtifact
from .trust import TrustStore


@dataclass(frozen=True)
class A2ATaskDelegation:
    """A cryptographically signed task delegation from one agent to another."""

    delegator_id: str
    recipient_id: str
    task_id: str
    action: str
    payload: dict[str, Any]
    gaa: GovernanceAuthorizationArtifact
    signature: str

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "action": self.action,
                "delegator_id": self.delegator_id,
                "gaa_nonce": self.gaa.nonce,
                "payload": self.payload,
                "recipient_id": self.recipient_id,
                "task_id": self.task_id,
            }
        )

    @classmethod
    def create(
        cls,
        *,
        delegator: KeyPair,
        recipient_id: str,
        task_id: str,
        action: str,
        payload: dict[str, Any],
        gaa: GovernanceAuthorizationArtifact,
    ) -> A2ATaskDelegation:
        """Create and sign a task delegation artifact."""
        if not recipient_id:
            raise ValueError("recipient_id must be a non-empty string")
        if not task_id:
            raise ValueError("task_id must be a non-empty string")
        if not action:
            raise ValueError("action must be a non-empty string")

        unsigned = cls(
            delegator_id=delegator.key_id,
            recipient_id=recipient_id,
            task_id=task_id,
            action=action,
            payload=payload,
            gaa=gaa,
            signature="",
        )
        sig = delegator.sign(unsigned.unsigned_payload())
        return cls(
            delegator_id=unsigned.delegator_id,
            recipient_id=unsigned.recipient_id,
            task_id=unsigned.task_id,
            action=unsigned.action,
            payload=unsigned.payload,
            gaa=unsigned.gaa,
            signature=sig,
        )

    def verify(self, delegator_public_key: Any) -> bool:
        """Verify the delegator's signature on the delegation envelope."""
        return verify_signature(delegator_public_key, self.unsigned_payload(), self.signature)

    def to_dict(self) -> dict[str, Any]:
        return {
            "delegator_id": self.delegator_id,
            "recipient_id": self.recipient_id,
            "task_id": self.task_id,
            "action": self.action,
            "payload": self.payload,
            "gaa": self.gaa.to_dict(),
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> A2ATaskDelegation:
        required = {
            "delegator_id",
            "recipient_id",
            "task_id",
            "action",
            "payload",
            "gaa",
            "signature",
        }
        if not isinstance(data, dict) or set(data.keys()) != required:
            raise ValueError(f"invalid A2ATaskDelegation dictionary: keys must be {required}")
        return cls(
            delegator_id=str(data["delegator_id"]),
            recipient_id=str(data["recipient_id"]),
            task_id=str(data["task_id"]),
            action=str(data["action"]),
            payload=dict(data["payload"]),
            gaa=GovernanceAuthorizationArtifact.from_dict(data["gaa"]),
            signature=str(data["signature"]),
        )


class A2AGuard:
    """
    Execution barrier for recipient agents in an A2A delegation flow.

    Verifies delegator signatures, recipient targeting, GAA tokens,
    and executes handlers through the GAS ExecutionBoundary.
    """

    def __init__(
        self,
        *,
        recipient_id: str,
        trust_store: TrustStore,
        boundary: ExecutionBoundary,
    ) -> None:
        self.recipient_id = recipient_id
        self.trust_store = trust_store
        self.boundary = boundary

    def receive_and_execute(
        self,
        delegation: A2ATaskDelegation,
        handler: Callable[[dict[str, Any]], Any],
    ) -> Any:
        """
        Verify incoming delegation and execute under the recipient's execution boundary.

        :raises AuthorizationError: If signature, recipient, action, or barrier check fails.
        """
        # 1. Verify recipient targeting
        if delegation.recipient_id != self.recipient_id:
            raise AuthorizationError(
                f"delegation recipient mismatch: intended for {delegation.recipient_id!r}, "
                f"received by {self.recipient_id!r}"
            )

        # 2. Verify delegator key in trust store
        delegator_key = self.trust_store.resolve(delegation.delegator_id)
        if delegator_key is None:
            raise AuthorizationError(f"unknown or revoked delegator key: {delegation.delegator_id!r}")

        # 3. Verify delegator signature on delegation envelope
        if not delegation.verify(delegator_key):
            raise AuthorizationError("invalid delegator signature on A2A delegation envelope")

        # 4. Verify GAA action matches task action
        gaa_action = delegation.gaa.action_request.get("action")
        if gaa_action != delegation.action:
            raise AuthorizationError(
                f"action mismatch between delegation ({delegation.action!r}) and "
                f"GAA ({gaa_action!r})"
            )

        # 5. Execute via standard GAS ExecutionBoundary (claims nonce, enforces policy, commits replay log)
        return self.boundary.execute(delegation.gaa, handler)
