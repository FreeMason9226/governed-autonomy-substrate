from typing import Any

from .mesh import GovernanceSourceRegistry
from .policy import PolicyRegistry
from .replay import ReplayLog
from .trust import TrustStore


def health_report(
    *,
    replay_log: ReplayLog,
    trust_store: TrustStore | None = None,
    policy_registry: PolicyRegistry | None = None,
    mesh_source_registry: GovernanceSourceRegistry | None = None,
) -> dict[str, Any]:
    checks: dict[str, dict[str, Any]] = {
        "replay_chain": {
            "ok": replay_log.verify_chain(),
            "frames": len(replay_log.frames),
        }
    }
    if trust_store is not None:
        checks["trust_store"] = {"ok": True}
    if policy_registry is not None:
        checks["policy_registry"] = {
            "ok": True,
            "policies": len(policy_registry.policies()),
        }
    if mesh_source_registry is not None:
        checks["mesh_source_registry"] = {
            "ok": True,
            "sources": len(mesh_source_registry._keys),
            "revoked": len(mesh_source_registry._revoked),
        }
    return {
        "ok": all(check["ok"] for check in checks.values()),
        "checks": checks,
    }
