"""Governed Autonomy Substrate MVP."""

from .a2a import A2AGuard, A2ATaskDelegation
from .auth.entra import EntraDeviceAuthorizationClient
from .auth.store import SQLiteIdentityStore
from .bootstrap import build_demo_service, build_runtime_service
from .compliance import ComplianceAuditor
from .control_plane import ControlPlane
from .crypto import KeyPair, verify_signature
from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .federation import (
    FederationError,
    GovernanceReconciler,
    GovernanceSyncEnvelope,
    RegistrySnapshot,
    SignedSyncEvent,
)
from .governance import GovernanceRuleTranslator
from .health import health_report
from .http_api import create_server, parse_server_args
from .identity import EntraOIDCConfig, ExternalIdentity, OIDCAuthCodeClient, OIDCDiscoveryDocument
from .issuer import AuthorizationIssuer, PolicyDeniedError
from .jobs import SQLiteJobStore, run_once
from .jobs_postgres import POSTGRES_JOBS_SCHEMA, PostgresJobStore
from .langchain_adapter import GASCallbackHandler, GASExecutionBarrierTool
from .mcp_gateway import GASMCPGateway, MCPGatewayContext
from .mesh import GovernanceInput, GovernanceMesh, GovernanceMeshError, GovernanceSourceRegistry
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .platform import (
    GovernancePlatform,
    PlatformDeploymentPolicy,
    RuntimeIdentity,
    ServicePrincipal,
    ServicePrincipalRegistry,
)
from .platform_admin import PolicyChangeManager, TrustChangeManager
from .policy import (
    DeterministicArbiter,
    Policy,
    PolicyRegistry,
    SignedPolicyManifest,
    signed_policy_manifest_from_dict,
)
from .replay import ReplayLog, SQLiteReplayLog
from .service import GovernedService
from .signing import KMSSigner
from .storage import PostgresReplayLog
from .trust import TrustStore

__all__ = [
    # Core Engine & Arbitration
    "ExecutionBoundary",
    "DeterministicArbiter",
    "AuthorizationIssuer",
    "PolicyRegistry",
    "Policy",
    "SignedPolicyManifest",
    "signed_policy_manifest_from_dict",
    "GovernanceRuleTranslator",

    # Platform & Mesh
    "GovernancePlatform",
    "PlatformDeploymentPolicy",
    "GovernanceMesh",
    "GovernanceInput",
    "GovernanceSourceRegistry",
    "GovernedService",
    "ServicePrincipal",
    "ServicePrincipalRegistry",
    "RuntimeIdentity",
    "PolicyChangeManager",
    "TrustChangeManager",

    # Security, Identity & Trust
    "TrustStore",
    "KeyPair",
    "verify_signature",
    "KMSSigner",
    "ExternalIdentity",
    "EntraDeviceAuthorizationClient",
    "SQLiteIdentityStore",
    "EntraOIDCConfig",
    "OIDCAuthCodeClient",
    "OIDCDiscoveryDocument",

    # Compliance & Audit
    "ComplianceAuditor",
    "ControlPlane",
    "ReplayLog",
    "SQLiteReplayLog",
    "GovernanceAuthorizationArtifact",
    "SignedApproval",
    "health_report",

    # Federation & Agent Integrations
    "GovernanceReconciler",
    "GovernanceSyncEnvelope",
    "RegistrySnapshot",
    "SignedSyncEvent",
    "A2AGuard",
    "A2ATaskDelegation",
    "GASMCPGateway",
    "MCPGatewayContext",
    "GASExecutionBarrierTool",
    "GASCallbackHandler",

    # Runtime bootstrap, HTTP API, and job/storage adapters
    "build_demo_service",
    "build_runtime_service",
    "create_server",
    "parse_server_args",
    "SQLiteJobStore",
    "PostgresJobStore",
    "POSTGRES_JOBS_SCHEMA",
    "run_once",
    "PostgresReplayLog",

    # Core Exceptions
    "AuthorizationError",
    "PolicyDeniedError",
    "GovernanceMeshError",
    "FederationError",
]
