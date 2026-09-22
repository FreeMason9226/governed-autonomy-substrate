import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .canonical import canonical_json
from .crypto import KeyPair, verify_signature


@dataclass(frozen=True)
class SignedApproval:
    """Bound approval evidence from a signer for an authorization request."""

    action: str
    request_digest: str
    decision_digest: str
    issuer_key_id: str
    signature: str
    actor_id: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "action": self.action,
                "request_digest": self.request_digest,
                "decision_digest": self.decision_digest,
                "issuer_key_id": self.issuer_key_id,
                "actor_id": self.actor_id,
                "context": self.context,
            }
        )

    @classmethod
    def issue(
        cls,
        *,
        action: str,
        request_digest: str,
        decision_digest: str,
        issuer: KeyPair,
        actor_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> "SignedApproval":
        unsigned = cls(
            action=action,
            request_digest=request_digest,
            decision_digest=decision_digest,
            issuer_key_id=issuer.key_id,
            signature="",
            actor_id=actor_id,
            context=context or {},
        )
        return cls(
            action=unsigned.action,
            request_digest=unsigned.request_digest,
            decision_digest=unsigned.decision_digest,
            issuer_key_id=unsigned.issuer_key_id,
            signature=issuer.sign(unsigned.unsigned_payload()),
            actor_id=unsigned.actor_id,
            context=unsigned.context,
        )

    def verify(self, public_key: Any) -> bool:
        return verify_signature(public_key, self.unsigned_payload(), self.signature)

    def matches_request(self, request: dict[str, Any], *, decision: dict[str, Any] | None = None) -> bool:
        if not isinstance(request, dict):
            return False
        if self.action != str(request.get("action")):
            return False
        request_without_approvals = {key: value for key, value in request.items() if key != "approvals"}
        digest = hashlib.sha256(canonical_json(request_without_approvals)).hexdigest()
        if self.request_digest != digest:
            return False
        if decision is None:
            return True
        return self.decision_digest == hashlib.sha256(canonical_json(decision)).hexdigest()

    @classmethod
    def from_request(
        cls,
        *,
        request: dict[str, Any],
        decision: dict[str, Any],
        issuer: KeyPair,
        actor_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> "SignedApproval":
        request_without_approvals = {
            key: value for key, value in request.items() if key != "approvals"
        }
        return cls.issue(
            action=str(request.get("action")),
            request_digest=hashlib.sha256(canonical_json(request_without_approvals)).hexdigest(),
            decision_digest=hashlib.sha256(canonical_json(decision)).hexdigest(),
            issuer=issuer,
            actor_id=actor_id,
            context=context,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "action": self.action,
            "request_digest": self.request_digest,
            "decision_digest": self.decision_digest,
            "issuer_key_id": self.issuer_key_id,
            "signature": self.signature,
        }
        if self.actor_id is not None:
            payload["actor_id"] = self.actor_id
        if self.context:
            payload["context"] = self.context
        return payload

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SignedApproval":
        expected = {"action", "request_digest", "decision_digest", "issuer_key_id", "signature"}
        if not isinstance(value, dict):
            raise ValueError("signed approval must be an object")
        if not set(value).issubset(expected | {"actor_id", "context"}):
            raise ValueError("signed approval has an invalid schema")
        if not set(value).issuperset(expected):
            raise ValueError("signed approval is missing required fields")

        if not isinstance(value["action"], str) or not value["action"]:
            raise ValueError("signed approval action must be a non-empty string")
        for key in ("request_digest", "decision_digest", "issuer_key_id", "signature"):
            if not isinstance(value[key], str) or not value[key]:
                raise ValueError(f"signed approval {key} must be a non-empty string")
        actor_id = value.get("actor_id")
        if actor_id is not None and (not isinstance(actor_id, str) or not actor_id):
            raise ValueError("signed approval actor_id must be a non-empty string when present")
        context = value.get("context", {})
        if not isinstance(context, dict):
            raise ValueError("signed approval context must be an object when present")
        return cls(
            action=value["action"],
            request_digest=value["request_digest"],
            decision_digest=value["decision_digest"],
            issuer_key_id=value["issuer_key_id"],
            signature=value["signature"],
            actor_id=actor_id,
            context=context,
        )


@dataclass(frozen=True)
class GovernanceAuthorizationArtifact:
    action_request: dict[str, Any]
    decision: dict[str, Any]
    expires_at: int
    nonce: str
    replay_frame_ref: str
    issuer_key_id: str
    signature: str

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "action_request": self.action_request,
                "decision": self.decision,
                "expires_at": self.expires_at,
                "nonce": self.nonce,
                "replay_frame_ref": self.replay_frame_ref,
                "issuer_key_id": self.issuer_key_id,
            }
        )

    @classmethod
    def issue(
        cls,
        *,
        action_request: dict[str, Any],
        decision: dict[str, Any],
        expires_at: int,
        nonce: str,
        replay_frame_ref: str,
        issuer: KeyPair,
    ) -> "GovernanceAuthorizationArtifact":
        unsigned = cls(
            action_request,
            decision,
            expires_at,
            nonce,
            replay_frame_ref,
            issuer.key_id,
            "",
        )
        return cls(
            **{
                **unsigned.__dict__,
                "signature": issuer.sign(unsigned.unsigned_payload()),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_request": self.action_request,
            "decision": self.decision,
            "expires_at": self.expires_at,
            "nonce": self.nonce,
            "replay_frame_ref": self.replay_frame_ref,
            "issuer_key_id": self.issuer_key_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "GovernanceAuthorizationArtifact":
        """Parse the transport form without coercing or silently defaulting fields."""
        required = {
            "action_request",
            "decision",
            "expires_at",
            "nonce",
            "replay_frame_ref",
            "issuer_key_id",
            "signature",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError("GAA must contain exactly the required fields")
        if not isinstance(value["action_request"], dict):
            raise ValueError("action_request must be an object")
        if not isinstance(value["decision"], dict):
            raise ValueError("decision must be an object")
        if not isinstance(value["expires_at"], int) or isinstance(
            value["expires_at"], bool
        ):
            raise ValueError("expires_at must be an integer")
        for field in ("nonce", "replay_frame_ref", "issuer_key_id", "signature"):
            if not isinstance(value[field], str) or not value[field]:
                raise ValueError(f"{field} must be a non-empty string")
        return cls(
            action_request=value["action_request"],
            decision=value["decision"],
            expires_at=value["expires_at"],
            nonce=value["nonce"],
            replay_frame_ref=value["replay_frame_ref"],
            issuer_key_id=value["issuer_key_id"],
            signature=value["signature"],
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, value: str) -> "GovernanceAuthorizationArtifact":
        if not isinstance(value, str):
            raise ValueError("GAA JSON must be a string")
        try:
            payload = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("GAA JSON is invalid") from exc
        return cls.from_dict(payload)
