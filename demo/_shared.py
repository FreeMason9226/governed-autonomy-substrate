"""Safe scenario composition over the actual GAS issuer, policy, and barrier."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from governed_autonomy import (
    AuthorizationIssuer,
    ExecutionBoundary,
    GovernanceAuthorizationArtifact,
    GovernedService,
    KeyPair,
    Policy,
    PolicyDeniedError,
    PolicyRegistry,
    ReplayLog,
    SignedApproval,
    TrustStore,
    verify_signature,
)
from governed_autonomy.canonical import canonical_json


@dataclass
class DemoRuntime:
    scenario: str
    service: GovernedService
    issuer: KeyPair
    approver: KeyPair
    trust_store: TrustStore
    policies: PolicyRegistry
    replay_log: ReplayLog
    state: dict[str, Any]
    evidence: list[dict[str, Any]]

    def approve(self, request: dict[str, Any], policy_id: str) -> SignedApproval:
        policy = self.policies.get(policy_id)
        if policy is None:
            raise ValueError(f"unknown demo policy: {policy_id}")
        decision = {
            "allow": True,
            "policy": policy.policy_id,
            "policy_digest": policy.digest(),
        }
        return SignedApproval.from_request(
            request=request,
            decision=decision,
            issuer=self.approver,
            actor_id="reviewer:demo-approver",
            context={"identity_source": "demo-review-key"},
        )

    def run(
        self,
        request: dict[str, Any],
        policy_id: str,
        *,
        approval: SignedApproval | None = None,
    ) -> dict[str, Any]:
        policy = self.policies.get(policy_id)
        if policy is None:
            raise ValueError(f"unknown demo policy: {policy_id}")
        try:
            artifact = self.service.authorize(
                request,
                policy_id,
                approvals=[approval] if approval is not None else None,
            )
        except PolicyDeniedError as exc:
            frame = self.replay_log.get(f"authorization:{self.replay_log.frames[-1].event['nonce']}")
            result = self._dashboard(
                request=request,
                policy=policy,
                decision=exc.decision,
                status="blocked",
                execution_result=None,
                gaa=None,
                approval=approval,
                authorization_event=frame.event if frame else None,
                execution_event=None,
            )
            self.evidence.append(result)
            return result

        public_key = self.trust_store.resolve(artifact.issuer_key_id)
        signature_valid = public_key is not None and verify_signature(
            public_key,
            artifact.unsigned_payload(),
            artifact.signature,
        )
        execution_result = self.service.execute(artifact)
        authorization_frame = self.replay_log.get(artifact.replay_frame_ref)
        execution_frame = self.replay_log.get(f"execution:{artifact.nonce}")
        result = self._dashboard(
            request=request,
            policy=policy,
            decision=artifact.decision,
            status="executed",
            execution_result=execution_result,
            gaa=artifact.to_dict(),
            approval=approval,
            authorization_event=authorization_frame.event if authorization_frame else None,
            execution_event=execution_frame.event if execution_frame else None,
            signature_valid=signature_valid,
        )
        self.evidence.append(result)
        return result

    def audit_report(self) -> dict[str, Any]:
        integrity = self.replay_log.verify_integrity()
        report = {
            "scenario": self.scenario,
            "generated_at": datetime.now(UTC).isoformat(),
            "integrity": integrity,
            "frames": [frame.to_dict() for frame in self.replay_log.frames],
            "runs": self.evidence,
        }
        report["report_digest"] = hashlib.sha256(canonical_json(report)).hexdigest()
        return report

    def _dashboard(
        self,
        *,
        request: dict[str, Any],
        policy: Policy,
        decision: dict[str, Any],
        status: str,
        execution_result: Any,
        gaa: dict[str, Any] | None,
        approval: SignedApproval | None,
        authorization_event: dict[str, Any] | None,
        execution_event: dict[str, Any] | None,
        signature_valid: bool = False,
    ) -> dict[str, Any]:
        approval_valid = bool(
            approval
            and self.trust_store.resolve(approval.issuer_key_id)
            and approval.verify(self.trust_store.resolve(approval.issuer_key_id))
        )
        nonce = gaa.get("nonce") if gaa else (
            authorization_event.get("nonce") if authorization_event else None
        )
        return {
            "requestor": request.get("context", {}).get("subject"),
            "approver": approval.actor_id if approval_valid and approval else None,
            "policy_evaluated": policy.policy_id,
            "policy_version": policy.policy_id,
            "policy_result": "allow" if decision.get("allow") else "deny",
            "reason": "; ".join(decision.get("reasons", [])) or "all configured controls passed",
            "reason_codes": decision.get("reason_codes", []),
            "gaa_identifier": gaa.get("replay_frame_ref") if gaa else None,
            "nonce": nonce,
            "timestamp": datetime.now(UTC).isoformat(),
            "status": status,
            "execution_result": execution_result,
            "signature_verified": signature_valid,
            "approver_signature_verified": approval_valid,
            "authorization_event": authorization_event,
            "execution_event": execution_event,
            "policy_digest": policy.digest(),
        }


def build_runtime(
    *,
    scenario: str,
    policies: tuple[Policy, ...],
    actions: tuple[str, ...],
    handler,
    state: dict[str, Any] | None = None,
) -> DemoRuntime:
    issuer = KeyPair.generate(f"{scenario}-gaa-issuer")
    approver = KeyPair.generate(f"{scenario}-review-approver")
    trust = TrustStore()
    trust.add(issuer.key_id, issuer.public_key)
    trust.add(approver.key_id, approver.public_key)
    registry = PolicyRegistry(policies)
    log = ReplayLog()
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=log),
        boundary=ExecutionBoundary(
            replay_log=log,
            trust_store=trust,
            policy_registry=registry,
        ),
        policies=registry,
        actions={action: handler for action in actions},
    )
    return DemoRuntime(
        scenario=scenario,
        service=service,
        issuer=issuer,
        approver=approver,
        trust_store=trust,
        policies=registry,
        replay_log=log,
        state=state if state is not None else {},
        evidence=[],
    )


def identity_context(subject: str, *, tenant: str = "gas-demo") -> dict[str, Any]:
    return {
        "subject": subject,
        "tenant_id": tenant,
        "identity_source": "demo-fixture",
        "roles": ["operator"],
        "environment": "dev",
    }

