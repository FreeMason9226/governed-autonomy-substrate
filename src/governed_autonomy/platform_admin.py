from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64decode, canonical_json
from .crypto import KeyPair, verify_signature
from .policy import Policy, PolicyRegistry
from .trust import TrustStore


@dataclass(frozen=True)
class PolicyApproval:
    proposal_id: str
    policy_id: str
    policy_digest: str
    approver_key_id: str
    signature: str

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "proposal_id": self.proposal_id,
                "policy_id": self.policy_id,
                "policy_digest": self.policy_digest,
                "approver_key_id": self.approver_key_id,
            }
        )

    @classmethod
    def issue(
        cls,
        *,
        proposal_id: str,
        policy_id: str,
        policy_digest: str,
        approver: KeyPair,
    ) -> PolicyApproval:
        return cls(
            proposal_id=proposal_id,
            policy_id=policy_id,
            policy_digest=policy_digest,
            approver_key_id=approver.key_id,
            signature=approver.sign(
                canonical_json(
                    {
                        "proposal_id": proposal_id,
                        "policy_id": policy_id,
                        "policy_digest": policy_digest,
                        "approver_key_id": approver.key_id,
                    }
                )
            ),
        )

    def verify(self, trust_store: TrustStore) -> bool:
        key = trust_store.resolve(self.approver_key_id)
        return key is not None and verify_signature(
            key,
            self.unsigned_payload(),
            self.signature,
        )


@dataclass(frozen=True)
class PolicyChangeProposal:
    proposal_id: str
    policy_id: str
    current_policy_digest: str
    proposed_policy: Policy
    proposed_by_key_id: str
    rationale: str
    status: str = "pending"
    signature: str = ""
    approvals: tuple[PolicyApproval, ...] = ()

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "proposal_id": self.proposal_id,
                "policy_id": self.policy_id,
                "current_policy_digest": self.current_policy_digest,
                "proposed_policy": self.proposed_policy.to_dict(),
                "proposed_by_key_id": self.proposed_by_key_id,
                "rationale": self.rationale,
                "status": self.status,
            }
        )

    @classmethod
    def propose(
        cls,
        *,
        proposal_id: str,
        policy: Policy,
        proposer: KeyPair,
        rationale: str,
        current_policy_digest: str,
    ) -> PolicyChangeProposal:
        payload = cls(
            proposal_id=proposal_id,
            policy_id=policy.policy_id,
            current_policy_digest=current_policy_digest,
            proposed_policy=policy,
            proposed_by_key_id=proposer.key_id,
            rationale=rationale,
            status="pending",
            signature="",
        )
        return cls(
            proposal_id=payload.proposal_id,
            policy_id=payload.policy_id,
            current_policy_digest=payload.current_policy_digest,
            proposed_policy=payload.proposed_policy,
            proposed_by_key_id=payload.proposed_by_key_id,
            rationale=payload.rationale,
            status=payload.status,
            signature=proposer.sign(payload.unsigned_payload()),
            approvals=payload.approvals,
        )

    def verify(self, trust_store: TrustStore) -> bool:
        key = trust_store.resolve(self.proposed_by_key_id)
        return key is not None and verify_signature(
            key,
            self.unsigned_payload(),
            self.signature,
        )

    def approval_count(self) -> int:
        return len({approval.approver_key_id for approval in self.approvals})

    def to_summary_dict(self) -> dict[str, Any]:
        """JSON-safe summary suitable for HTTP responses (no private key material)."""
        return {
            "proposal_id": self.proposal_id,
            "policy_id": self.policy_id,
            "current_policy_digest": self.current_policy_digest,
            "proposed_policy": self.proposed_policy.to_dict(),
            "proposed_policy_digest": self.proposed_policy.digest(),
            "proposed_by_key_id": self.proposed_by_key_id,
            "rationale": self.rationale,
            "status": self.status,
            "approval_count": self.approval_count(),
            "approvals": [
                {"approver_key_id": approval.approver_key_id}
                for approval in sorted(self.approvals, key=lambda item: item.approver_key_id)
            ],
        }


class PolicyChangeManager:
    """Review and activate policy changes with explicit quorum approval."""

    def __init__(
        self,
        *,
        registry: PolicyRegistry,
        trust_store: TrustStore,
        required_approvals: int = 2,
        enforce_separation_of_duties: bool = True,
        audit_hook=None,
    ) -> None:
        if required_approvals <= 0:
            raise ValueError("required_approvals must be positive")
        self.registry = registry
        self.trust_store = trust_store
        self.required_approvals = required_approvals
        self.enforce_separation_of_duties = enforce_separation_of_duties
        self.audit_hook = audit_hook
        self._proposals: dict[str, PolicyChangeProposal] = {}

    def _proposal_id_and_digest(
        self, new_policy: Policy, proposal_id: str | None
    ) -> tuple[str, str]:
        existing = self.registry.get(new_policy.policy_id)
        current_digest = existing.digest() if existing is not None else ""
        resolved_id = proposal_id or (
            f"policy-proposal:{new_policy.policy_id}:{current_digest or 'new'}"
        )
        return resolved_id, current_digest

    def propose(
        self,
        *,
        new_policy: Policy,
        proposer: KeyPair,
        rationale: str = "",
        proposal_id: str | None = None,
    ) -> PolicyChangeProposal:
        key = self.trust_store.resolve(proposer.key_id)
        if key is None:
            raise ValueError("proposer key is not trusted")
        resolved_id, current_digest = self._proposal_id_and_digest(new_policy, proposal_id)
        proposal = PolicyChangeProposal.propose(
            proposal_id=resolved_id,
            policy=new_policy,
            proposer=proposer,
            rationale=rationale,
            current_policy_digest=current_digest,
        )
        if not proposal.verify(self.trust_store):
            raise ValueError("proposal signature is invalid")
        self._register_new_proposal(proposal)
        return proposal

    def prepare_proposal(
        self,
        *,
        new_policy: Policy,
        proposer_key_id: str,
        rationale: str = "",
        proposal_id: str | None = None,
    ) -> dict[str, Any]:
        """Return the exact bytes an external signer must sign to submit this proposal.

        Used by clients (e.g. the admin browser UI) that hold a private key
        outside the server process: they fetch this payload, sign it locally,
        and submit the signature to :meth:`propose_signed` without ever having
        to reimplement the server's canonicalization logic. ``proposer_key_id``
        must match the key used to sign, since it is part of the signed
        payload (see :meth:`PolicyChangeProposal.unsigned_payload`).
        """
        resolved_id, current_digest = self._proposal_id_and_digest(new_policy, proposal_id)
        draft = PolicyChangeProposal(
            proposal_id=resolved_id,
            policy_id=new_policy.policy_id,
            current_policy_digest=current_digest,
            proposed_policy=new_policy,
            proposed_by_key_id=proposer_key_id,
            rationale=rationale,
            status="pending",
        )
        return {
            "proposal_id": resolved_id,
            "current_policy_digest": current_digest,
            "unsigned_payload": draft.unsigned_payload().decode("utf-8"),
        }

    def propose_signed(
        self,
        *,
        new_policy: Policy,
        proposer_key_id: str,
        signature: str,
        rationale: str = "",
        proposal_id: str | None = None,
    ) -> PolicyChangeProposal:
        """Register a proposal whose signature was produced outside this process.

        The signature must cover the exact payload returned by
        :meth:`prepare_proposal` for the same ``new_policy``/``rationale``/
        ``proposal_id`` (a mismatch of any field changes the signed bytes and
        fails verification, closing the loop safely).
        """
        if self.trust_store.resolve(proposer_key_id) is None:
            raise ValueError("proposer key is not trusted")
        resolved_id, current_digest = self._proposal_id_and_digest(new_policy, proposal_id)
        proposal = PolicyChangeProposal(
            proposal_id=resolved_id,
            policy_id=new_policy.policy_id,
            current_policy_digest=current_digest,
            proposed_policy=new_policy,
            proposed_by_key_id=proposer_key_id,
            rationale=rationale,
            status="pending",
            signature=signature,
        )
        if not proposal.verify(self.trust_store):
            raise ValueError("proposal signature is invalid")
        self._register_new_proposal(proposal)
        return proposal

    def _register_new_proposal(self, proposal: PolicyChangeProposal) -> None:
        if proposal.proposal_id in self._proposals:
            raise ValueError(f"proposal already exists: {proposal.proposal_id}")
        self._proposals[proposal.proposal_id] = proposal
        if self.audit_hook is not None:
            self.audit_hook("policy.proposed", proposal.proposal_id)

    def approve(
        self,
        proposal_id: str,
        *,
        approver: KeyPair,
    ) -> PolicyChangeProposal:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown policy proposal: {proposal_id}")
        if proposal.status != "pending":
            raise ValueError("proposal is no longer pending")
        if self.enforce_separation_of_duties and approver.key_id == proposal.proposed_by_key_id:
            raise ValueError("proposer cannot approve the same policy change")
        key = self.trust_store.resolve(approver.key_id)
        if key is None:
            raise ValueError("approver key is not trusted")
        approval = PolicyApproval.issue(
            proposal_id=proposal.proposal_id,
            policy_id=proposal.policy_id,
            policy_digest=proposal.proposed_policy.digest(),
            approver=approver,
        )
        if not approval.verify(self.trust_store):
            raise ValueError("approval signature is invalid")
        approvals = tuple(
            sorted(
                [*proposal.approvals, approval],
                key=lambda item: item.approver_key_id,
            )
        )
        updated = replace(proposal, approvals=approvals)
        self._proposals[proposal_id] = updated
        if self.audit_hook is not None:
            self.audit_hook("policy.approved", proposal_id)
        return updated

    def prepare_approval(self, proposal_id: str, *, approver_key_id: str) -> dict[str, Any]:
        """Return the exact bytes an external approver must sign for this proposal.

        Mirrors :meth:`prepare_proposal` for the approval step, so a browser
        client never needs to reconstruct the server's canonical JSON.
        ``approver_key_id`` must match the key used to sign, since it is part
        of the signed payload (see :meth:`PolicyApproval.unsigned_payload`).
        """
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown policy proposal: {proposal_id}")
        if proposal.status != "pending":
            raise ValueError("proposal is no longer pending")
        policy_digest = proposal.proposed_policy.digest()
        draft = PolicyApproval(
            proposal_id=proposal.proposal_id,
            policy_id=proposal.policy_id,
            policy_digest=policy_digest,
            approver_key_id=approver_key_id,
            signature="",
        )
        return {
            "policy_digest": policy_digest,
            "unsigned_payload": draft.unsigned_payload().decode("utf-8"),
        }

    def approve_signed(
        self,
        proposal_id: str,
        *,
        approver_key_id: str,
        signature: str,
    ) -> PolicyChangeProposal:
        """Record an approval whose signature was produced outside this process.

        The signature must cover the exact payload returned by
        :meth:`prepare_approval` for this proposal.
        """
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown policy proposal: {proposal_id}")
        if proposal.status != "pending":
            raise ValueError("proposal is no longer pending")
        if self.enforce_separation_of_duties and approver_key_id == proposal.proposed_by_key_id:
            raise ValueError("proposer cannot approve the same policy change")
        if approver_key_id in {approval.approver_key_id for approval in proposal.approvals}:
            raise ValueError("this key has already approved the proposal")
        if self.trust_store.resolve(approver_key_id) is None:
            raise ValueError("approver key is not trusted")
        approval = PolicyApproval(
            proposal_id=proposal.proposal_id,
            policy_id=proposal.policy_id,
            policy_digest=proposal.proposed_policy.digest(),
            approver_key_id=approver_key_id,
            signature=signature,
        )
        if not approval.verify(self.trust_store):
            raise ValueError("approval signature is invalid")
        approvals = tuple(
            sorted(
                [*proposal.approvals, approval],
                key=lambda item: item.approver_key_id,
            )
        )
        updated = replace(proposal, approvals=approvals)
        self._proposals[proposal_id] = updated
        if self.audit_hook is not None:
            self.audit_hook("policy.approved", proposal_id)
        return updated

    def activate(self, proposal_id: str) -> Policy:
        proposal = self._proposals.get(proposal_id)
        if proposal is None:
            raise KeyError(f"unknown policy proposal: {proposal_id}")
        if proposal.status != "pending":
            raise ValueError("proposal is not pending")
        if not proposal.verify(self.trust_store):
            raise ValueError("proposal signature is invalid")
        if proposal.approval_count() < self.required_approvals:
            raise ValueError("approval quorum not met")
        self.registry.register(proposal.proposed_policy)
        updated = replace(proposal, status="activated")
        self._proposals[proposal_id] = updated
        if self.audit_hook is not None:
            self.audit_hook("policy.activated", proposal_id)
        return proposal.proposed_policy

    def get(self, proposal_id: str) -> PolicyChangeProposal | None:
        return self._proposals.get(proposal_id)

    def proposals(self) -> tuple[PolicyChangeProposal, ...]:
        return tuple(self._proposals[key] for key in sorted(self._proposals))


@dataclass(frozen=True)
class TrustChangeRequest:
    """A signed request to add or revoke a trusted issuer key.

    Trust changes take effect immediately once signed by any *currently
    trusted, non-revoked* key -- unlike policy changes there is no separate
    approval quorum, since trust is the root of authority the quorum itself
    depends on. Bootstrapping the very first trusted key remains an
    out-of-band operation (see ``bootstrap.py``).
    """

    action: str
    key_id: str
    public_key_b64: str
    requested_by_key_id: str
    signature: str = ""

    def __post_init__(self) -> None:
        if self.action not in {"add", "revoke"}:
            raise ValueError("action must be 'add' or 'revoke'")

    def unsigned_payload(self) -> bytes:
        return canonical_json(
            {
                "action": self.action,
                "key_id": self.key_id,
                "public_key_b64": self.public_key_b64,
                "requested_by_key_id": self.requested_by_key_id,
            }
        )

    def verify(self, trust_store: TrustStore) -> bool:
        key = trust_store.resolve(self.requested_by_key_id)
        return key is not None and verify_signature(
            key,
            self.unsigned_payload(),
            self.signature,
        )


class TrustChangeManager:
    """Add and revoke trusted issuer keys via signatures from existing trusted keys."""

    def __init__(self, *, trust_store: TrustStore, audit_hook=None) -> None:
        self.trust_store = trust_store
        self.audit_hook = audit_hook

    def prepare_add(self, *, key_id: str, public_key_b64: str, requested_by_key_id: str) -> dict[str, Any]:
        draft = TrustChangeRequest(
            action="add",
            key_id=key_id,
            public_key_b64=public_key_b64,
            requested_by_key_id=requested_by_key_id,
        )
        return {"unsigned_payload": draft.unsigned_payload().decode("utf-8")}

    def submit_add(
        self,
        *,
        key_id: str,
        public_key_b64: str,
        requested_by_key_id: str,
        signature: str,
    ) -> dict[str, Any]:
        request = TrustChangeRequest(
            action="add",
            key_id=key_id,
            public_key_b64=public_key_b64,
            requested_by_key_id=requested_by_key_id,
            signature=signature,
        )
        if not request.verify(self.trust_store):
            raise ValueError("trust change signature is invalid")
        try:
            public_key = Ed25519PublicKey.from_public_bytes(b64decode(public_key_b64))
        except (ValueError, TypeError) as exc:
            raise ValueError("public_key_b64 is not a valid Ed25519 public key") from exc
        self.trust_store.add(key_id, public_key)
        if self.audit_hook is not None:
            self.audit_hook("trust.key_added", key_id)
        return self.trust_store.to_dict()

    def prepare_revoke(self, key_id: str, *, requested_by_key_id: str) -> dict[str, Any]:
        draft = TrustChangeRequest(
            action="revoke",
            key_id=key_id,
            public_key_b64="",
            requested_by_key_id=requested_by_key_id,
        )
        return {"unsigned_payload": draft.unsigned_payload().decode("utf-8")}

    def submit_revoke(self, key_id: str, *, requested_by_key_id: str, signature: str) -> dict[str, Any]:
        request = TrustChangeRequest(
            action="revoke",
            key_id=key_id,
            public_key_b64="",
            requested_by_key_id=requested_by_key_id,
            signature=signature,
        )
        if not request.verify(self.trust_store):
            raise ValueError("trust change signature is invalid")
        self.trust_store.revoke(key_id)
        if self.audit_hook is not None:
            self.audit_hook("trust.key_revoked", key_id)
        return self.trust_store.to_dict()
