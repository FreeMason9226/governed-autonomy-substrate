import hashlib
import time
from collections.abc import Callable
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json
from .crypto import verify_signature
from .errors import AuthorizationError
from .models import GovernanceAuthorizationArtifact
from .mesh import GovernanceInput, GovernanceMesh, GovernanceMeshError
from .policy import DeterministicArbiter, PolicyRegistry
from .replay import ReplayFrame, ReplayLog
from .trust import TrustStore


class ExecutionBoundary:
    def __init__(
        self,
        *,
        replay_log: ReplayLog,
        issuer_keys: dict[str, Ed25519PublicKey] | None = None,
        trust_store: TrustStore | None = None,
        policy_registry: PolicyRegistry | None = None,
        clock: Callable[[], int] | None = None,
        arbiter: DeterministicArbiter | None = None,
    ) -> None:
        if (issuer_keys is None) == (trust_store is None):
            raise ValueError("provide exactly one of issuer_keys or trust_store")
        self.replay_log = replay_log
        self.issuer_keys = issuer_keys
        self.trust_store = trust_store
        self.policy_registry = policy_registry
        self.clock = clock or (lambda: int(time.time()))
        self.arbiter = arbiter or DeterministicArbiter()

    @staticmethod
    def _result_audit(result: Any) -> dict[str, Any]:
        try:
            encoded = canonical_json(result)
        except (TypeError, ValueError):
            return {"result_omitted": True, "result_omission_reason": "not-json"}
        audit = {
            "result_digest": hashlib.sha256(encoded).hexdigest(),
            "result_bytes": len(encoded),
        }
        if len(encoded) <= 4096:
            audit["result"] = result
        else:
            audit["result_omitted"] = True
            audit["result_omission_reason"] = "size-limit"
        return audit

    def execute(
        self,
        artifact: GovernanceAuthorizationArtifact,
        action: Callable[[dict[str, Any]], Any],
    ) -> Any:
        self._validate(artifact)
        try:
            self.replay_log.claim_nonce(artifact.nonce)
        except ValueError as exc:
            raise AuthorizationError("GAA nonce has already been used") from exc
        try:
            result = action(artifact.action_request)
        except Exception as exc:
            self.replay_log.append(
                f"execution:{artifact.nonce}",
                {
                    "type": "execution",
                    "nonce": artifact.nonce,
                    "authorization_frame_ref": artifact.replay_frame_ref,
                    "policy": artifact.decision.get("policy"),
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:512],
                },
            )
            raise
        self.replay_log.append(
            f"execution:{artifact.nonce}",
            {
                "type": "execution",
                "nonce": artifact.nonce,
                "authorization_frame_ref": artifact.replay_frame_ref,
                "policy": artifact.decision.get("policy"),
                "status": "completed",
                **self._result_audit(result),
            },
        )
        return result

    def _validate(self, artifact: GovernanceAuthorizationArtifact) -> None:
        key = (
            self.trust_store.resolve(artifact.issuer_key_id)
            if self.trust_store
            else self.issuer_keys.get(artifact.issuer_key_id)
        )
        if key is None or not verify_signature(
            key, artifact.unsigned_payload(), artifact.signature
        ):
            raise AuthorizationError("GAA signature is invalid or issuer is unknown")
        if self.clock() >= artifact.expires_at:
            raise AuthorizationError("GAA is expired")
        if self.replay_log.nonce_used(artifact.nonce):
            raise AuthorizationError("GAA nonce has already been used")
        frame = self.replay_log.get(artifact.replay_frame_ref)
        if frame is None or frame.event.get("type") != "authorization":
            raise AuthorizationError("authorization replay frame is missing")
        if frame.event.get("nonce") != artifact.nonce:
            raise AuthorizationError("nonce does not match authorization frame")
        if frame.event.get("artifact_payload") != artifact.unsigned_payload().decode("utf-8"):
            raise AuthorizationError("authorization frame does not match GAA")
        self._validate_mesh_evidence(artifact, frame)
        if artifact.decision.get("allow") is not True:
            raise AuthorizationError("policy decision does not allow execution")
        if self.policy_registry is not None:
            policy_id = artifact.decision.get("policy")
            policy = self.policy_registry.get(policy_id)
            if policy is None:
                raise AuthorizationError("GAA policy is not registered")
            expected_digest = artifact.decision.get("policy_digest")
            if expected_digest is not None and expected_digest != policy.digest():
                raise AuthorizationError("GAA policy digest does not match registry")
            decision = self.arbiter.decide(artifact.action_request, policy)
            if not decision["allow"]:
                raise AuthorizationError(
                    "action request violates policy constraints: "
                    + "; ".join(decision["reasons"])
                    + " ["
                    + ",".join(decision["reason_codes"])
                    + "]"
                )
        allowed_actions = artifact.decision.get("allowed_actions")
        requested_action = artifact.action_request.get("action")
        if not isinstance(allowed_actions, list) or requested_action not in allowed_actions:
            raise AuthorizationError("requested action is outside policy constraints")

    def _validate_mesh_evidence(
        self, artifact: GovernanceAuthorizationArtifact, frame: ReplayFrame
    ) -> None:
        event = frame.event
        digest = artifact.decision.get("mesh_preflight_digest")
        evidence_keys = {"mesh_preflight_digest", "mesh_request_digest", "mesh_inputs"}
        has_evidence = any(key in event for key in evidence_keys)
        if digest is None:
            if has_evidence:
                raise AuthorizationError("mesh evidence is present without a signed mesh digest")
            return
        if not isinstance(digest, str) or not digest:
            raise AuthorizationError("mesh preflight digest is malformed")
        if not evidence_keys.issubset(event):
            raise AuthorizationError("mesh evidence is incomplete")
        if event["mesh_preflight_digest"] != digest:
            raise AuthorizationError("mesh evidence digest does not match signed decision")
        request_digest = hashlib.sha256(canonical_json(artifact.action_request)).hexdigest()
        if event["mesh_request_digest"] != request_digest:
            raise AuthorizationError("mesh evidence does not match the authorized request")
        raw_inputs = event["mesh_inputs"]
        if not isinstance(raw_inputs, list) or not raw_inputs:
            raise AuthorizationError("mesh evidence inputs are malformed")
        try:
            inputs = tuple(GovernanceInput.from_dict(item) for item in raw_inputs)
            decision = GovernanceMesh().preflight(inputs, request_digest=request_digest)
        except (GovernanceMeshError, TypeError, ValueError) as exc:
            raise AuthorizationError("mesh evidence is invalid") from exc
        if not decision.allow or decision.digest != digest:
            raise AuthorizationError("mesh evidence does not reconstruct to the signed digest")
        expected = ReplayFrame.create(frame.frame_id, frame.previous_hash, frame.event)
        if expected.frame_hash != frame.frame_hash:
            raise AuthorizationError("mesh authorization replay evidence is tampered")
