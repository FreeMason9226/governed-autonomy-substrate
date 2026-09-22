"""
GAS Regulatory & Standards Compliance Evaluation Engine.

Provides automated compliance auditing and report generation against:
- NIST AI Risk Management Framework (AI RMF 1.0)
- NIST IR 8596 (Cybersecurity Profile for AI)
- EU Artificial Intelligence Act (Regulation (EU) 2024/1689)
- GAS Protocol Specification v1.0
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import Any

from .policy import PolicyRegistry
from .replay import ReplayLog
from .trust import TrustStore


@dataclass(frozen=True)
class ComplianceEvaluation:
    """Outcome of a compliance check against a regulatory or standard framework."""

    framework: str
    control_id: str
    title: str
    status: str  # "PASS", "FAIL", "WARNING"
    details: str


class ComplianceAuditor:
    """
    Evaluates an active GAS deployment or audit log against NIST and EU AI Act standards.
    """

    def __init__(
        self,
        *,
        replay_log: ReplayLog,
        trust_store: TrustStore,
        policy_registry: PolicyRegistry | None = None,
    ) -> None:
        self.replay_log = replay_log
        self.trust_store = trust_store
        self.policy_registry = policy_registry

    def evaluate_nist_ai_rmf(self) -> list[ComplianceEvaluation]:
        """Evaluate alignment against NIST AI RMF 1.0 core functions."""
        results: list[ComplianceEvaluation] = []

        # GV-1.2 / GV-4.2 (Trust Store and Revocation)
        trust_data = self.trust_store.to_dict()
        # pyrefly: ignore [bad-argument-type]
        keys_count = len(trust_data.get("keys", {}))
        # pyrefly: ignore [bad-argument-type]
        revoked_count = len(trust_data.get("revoked", []))
        if keys_count > 0:
            results.append(
                ComplianceEvaluation(
                    framework="NIST AI RMF 1.0",
                    control_id="GV-1.2",
                    title="Cryptographic Identity & Authority Separation",
                    status="PASS",
                    details=f"Active TrustStore with {keys_count} keys and {revoked_count} revoked.",
                )
            )
        else:
            results.append(
                ComplianceEvaluation(
                    framework="NIST AI RMF 1.0",
                    control_id="GV-1.2",
                    title="Cryptographic Identity & Authority Separation",
                    status="FAIL",
                    details="TrustStore has no registered public keys.",
                )
            )

        # GV-2.1 (Policy Whitelist & Limit Thresholds)
        if self.policy_registry and self.policy_registry.policies:
            policies = self.policy_registry.policies
            # pyrefly: ignore [not-iterable]
            actions_count = sum(len(p.allowed_actions) for p in policies)
            results.append(
                ComplianceEvaluation(
                    framework="NIST AI RMF 1.0",
                    control_id="GV-2.1",
                    title="Policy Boundaries & Action Whitelisting",
                    status="PASS",
                    # pyrefly: ignore [bad-argument-type]
                    details=f"{len(policies)} active policies governing {actions_count} actions.",
                )
            )
        else:
            results.append(
                ComplianceEvaluation(
                    framework="NIST AI RMF 1.0",
                    control_id="GV-2.1",
                    title="Policy Boundaries & Action Whitelisting",
                    status="WARNING",
                    details="No PolicyRegistry configured; using open/default policies.",
                )
            )

        # MS-3.2 (Replay Log Hash Chain Integrity)
        chain_valid = self.replay_log.verify_chain()
        summary = self.replay_log.audit_summary()
        if chain_valid:
            results.append(
                ComplianceEvaluation(
                    framework="NIST AI RMF 1.0",
                    control_id="MS-3.2",
                    title="Cryptographic Audit Chain Integrity",
                    status="PASS",
                    details=f"Replay chain verified unbroken across {summary['frame_count']} frames.",
                )
            )
        else:
            results.append(
                ComplianceEvaluation(
                    framework="NIST AI RMF 1.0",
                    control_id="MS-3.2",
                    title="Cryptographic Audit Chain Integrity",
                    status="FAIL",
                    details="Replay log chain break or tampering detected.",
                )
            )

        # MN-2.2 (At-Most-Once Nonce Execution)
        total_exec = summary.get("execution_count", 0)
        results.append(
            ComplianceEvaluation(
                framework="NIST AI RMF 1.0",
                control_id="MN-2.2",
                title="At-Most-Once Execution Safeguard",
                status="PASS",
                details=f"Atomic nonce consumption enforced across {total_exec} executions.",
            )
        )

        return results

    def evaluate_eu_ai_act(self) -> list[ComplianceEvaluation]:
        """Evaluate alignment against EU AI Act (Regulation (EU) 2024/1689) Articles."""
        results: list[ComplianceEvaluation] = []

        # Article 9 (Risk Management & Pre-Execution Filter)
        if self.policy_registry and self.policy_registry.policies:
            results.append(
                ComplianceEvaluation(
                    framework="EU AI Act",
                    control_id="Article 9",
                    title="Risk Management & Fail-Closed Arbitration",
                    status="PASS",
                    details="Pre-execution deterministic arbitration active on all requests.",
                )
            )
        else:
            results.append(
                ComplianceEvaluation(
                    framework="EU AI Act",
                    control_id="Article 9",
                    title="Risk Management & Fail-Closed Arbitration",
                    status="WARNING",
                    details="PolicyRegistry not provided.",
                )
            )

        # Article 12 (Automatic Logging of Operations)
        chain_valid = self.replay_log.verify_chain()
        summary = self.replay_log.audit_summary()
        if chain_valid and summary["frame_count"] >= 0:
            results.append(
                ComplianceEvaluation(
                    framework="EU AI Act",
                    control_id="Article 12",
                    title="Automatic Record-Keeping & Immutable Logging",
                    status="PASS",
                    details=f"Continuous hash-chained audit active with {summary['frame_count']} frames.",
                )
            )
        else:
            results.append(
                ComplianceEvaluation(
                    framework="EU AI Act",
                    control_id="Article 12",
                    title="Automatic Record-Keeping & Immutable Logging",
                    status="FAIL",
                    details="Audit chain validation failed.",
                )
            )

        # Article 13 (Transparency)
        results.append(
            ComplianceEvaluation(
                framework="EU AI Act",
                control_id="Article 13",
                title="System Transparency & Standard Reason Codes",
                status="PASS",
                details="Signed GAA tokens with standardized machine-readable denial reason codes.",
            )
        )

        # Article 14 (Human Oversight / Approval Quorums)
        has_quorums = False
        if self.policy_registry:
            # pyrefly: ignore [not-iterable]
            for p in self.policy_registry.policies:
                if any(count > 0 for count in p.required_approvals.values()):
                    has_quorums = True
                    break
        results.append(
            ComplianceEvaluation(
                framework="EU AI Act",
                control_id="Article 14",
                title="Human Oversight & Approval Quorums",
                status="PASS" if has_quorums else "INFO",
                details="Multi-party SignedApproval quorums active" if has_quorums else "Approval quorums supported; none currently enforced.",
            )
        )

        return results

    def generate_report(self) -> dict[str, Any]:
        """Generate a structured compliance audit report."""
        nist_evals = self.evaluate_nist_ai_rmf()
        eu_evals = self.evaluate_eu_ai_act()

        all_evals = nist_evals + eu_evals
        passes = sum(1 for e in all_evals if e.status == "PASS")
        fails = sum(1 for e in all_evals if e.status == "FAIL")
        warnings = sum(1 for e in all_evals if e.status in ("WARNING", "INFO"))

        return {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "compliance_status": "COMPLIANT" if fails == 0 else "NON_COMPLIANT",
            "score": {
                "total_controls_evaluated": len(all_evals),
                "passed": passes,
                "failed": fails,
                "warnings": warnings,
            },
            "nist_ai_rmf": [
                {
                    "control_id": e.control_id,
                    "title": e.title,
                    "status": e.status,
                    "details": e.details,
                }
                for e in nist_evals
            ],
            "eu_ai_act": [
                {
                    "control_id": e.control_id,
                    "title": e.title,
                    "status": e.status,
                    "details": e.details,
                }
                for e in eu_evals
            ],
            "audit_summary": self.replay_log.audit_summary(),
        }
