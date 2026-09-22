import secrets
import time
from collections.abc import Callable, Sequence
from typing import Any

from .crypto import KeyPair
from .errors import AuthorizationError
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .policy import DeterministicArbiter, Policy
from .replay import ReplayLog


class PolicyDeniedError(AuthorizationError):
    """Raised when arbitration denies a request before a GAA is issued."""

    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        super().__init__(
            "policy denied authorization: "
            + "; ".join(decision["reasons"])
            + " ["
            + ",".join(decision["reason_codes"])
            + "]"
        )


class AuthorizationIssuer:
    """Arbitrate, audit, and issue signed GAAs as one explicit workflow."""

    def __init__(
        self,
        *,
        issuer: KeyPair,
        replay_log: ReplayLog,
        arbiter: DeterministicArbiter | None = None,
        clock: Callable[[], int] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> None:
        self.issuer = issuer
        self.replay_log = replay_log
        self.arbiter = arbiter or DeterministicArbiter()
        self.clock = clock or (lambda: int(time.time()))
        self.nonce_factory = nonce_factory or (lambda: secrets.token_urlsafe(24))

    def authorize(
        self,
        request: dict[str, Any],
        policy: Policy,
        *,
        ttl_seconds: int = 300,
        approvals: Sequence[SignedApproval | dict[str, Any]] | None = None,
    ) -> GovernanceAuthorizationArtifact:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if ttl_seconds > policy.max_ttl_seconds:
            raise ValueError("ttl_seconds exceeds policy maximum")
        effective_request = dict(request)
        if approvals is not None:
            serialized = []
            for approval in approvals:
                if isinstance(approval, SignedApproval):
                    serialized.append(approval.to_dict())
                elif isinstance(approval, dict):
                    serialized.append(dict(approval))
                else:
                    raise ValueError("approvals must be SignedApproval instances or objects")
            existing = effective_request.get("approvals")
            if existing is None:
                effective_request["approvals"] = serialized
            elif isinstance(existing, (list, tuple)):
                effective_request["approvals"] = [*list(existing), *serialized]
            else:
                raise ValueError("request approvals must be a list when present")
        decision = self.arbiter.decide(effective_request, policy)
        nonce = self.nonce_factory()
        frame_id = f"authorization:{nonce}"
        if not decision["allow"]:
            self.replay_log.append(
                frame_id,
                {
                    "type": "authorization",
                    "nonce": nonce,
                    "request": effective_request,
                    "decision": decision,
                    "issued": False,
                },
            )
            raise PolicyDeniedError(decision)

        expires_at = self.clock() + ttl_seconds
        unsigned = GovernanceAuthorizationArtifact(
            effective_request,
            decision,
            expires_at,
            nonce,
            frame_id,
            self.issuer.key_id,
            "",
        )
        self.replay_log.append(
            frame_id,
            {
                "type": "authorization",
                "nonce": nonce,
                "artifact_payload": unsigned.unsigned_payload().decode("utf-8"),
                "decision": decision,
                "issued": True,
            },
        )
        return GovernanceAuthorizationArtifact.issue(
            action_request=effective_request,
            decision=decision,
            expires_at=expires_at,
            nonce=nonce,
            replay_frame_ref=frame_id,
            issuer=self.issuer,
        )

    def authorize_compensation(
        self,
        failed_nonce: str,
        request: dict[str, Any],
        policy: Policy,
        *,
        ttl_seconds: int = 300,
    ) -> GovernanceAuthorizationArtifact:
        """Issue a new GAA only for a nonce with an audited failed execution."""
        if not failed_nonce:
            raise ValueError("failed_nonce must not be empty")
        failed = any(
            event.get("type") == "execution" and event.get("status") == "failed"
            for event in self.replay_log.events_for_nonce(failed_nonce)
        )
        if not failed:
            raise AuthorizationError("compensation requires an audited failed execution")
        compensated_request = {**request, "compensation_for": failed_nonce}
        return self.authorize(compensated_request, policy, ttl_seconds=ttl_seconds)
