"""Governed Autonomy Substrate MVP."""

from .a2a import A2AGuard, A2ATaskDelegation
from .bootstrap import build_demo_service, build_platform_demo, build_runtime_service
from .compliance import ComplianceAuditor, ComplianceEvaluation
from .crypto import KeyPair, verify_signature
from .deployment import (
    BoundedRateLimiter,
    TLSConfig,
    correlation_id,
    security_headers,
    validate_server_config,
)
from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .federation import (
    FederationError,
    GovernanceReconciler,
    GovernanceSyncEnvelope,
    ReconciliationResult,
    RegistrySnapshot,
    SignedSyncEvent,
)
from .governance import GovernanceRule, GovernanceRuleTranslator
from .health import health_report
from .http_api import AuthenticatedAPI, create_server, parse_server_args
from .identity import (
    ExternalIdentity,
    IdentityValidationError,
    JWKSProvider,
    JWTValidator,
    OIDCDiscoveryDocument,
    OIDCValidator,
    StaticJWKSProvider,
    UrlJWKSProvider,
    discover_oidc_configuration,
    oidc_validator_from_discovery,
)
from .issuer import AuthorizationIssuer, PolicyDeniedError
from .jobs import Job, SQLiteJobStore, run_once
from .langchain_adapter import GASCallbackHandler, GASExecutionBarrierTool, GASToolOutput
from .mcp_gateway import (
    GASMCPGateway,
    GASMCPServer,
    MCPGatewayContext,
    MCPToolDefinition,
    MCPToolResult,
)
from .mesh import (
    GovernanceInput,
    GovernanceMesh,
    GovernanceMeshError,
    GovernancePreflightDecision,
    GovernanceSourceRegistry,
)
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .operator_auth import OperatorAPIKey, OperatorKeyStore
from .platform import (
    GovernancePlatform,
    PlatformDeploymentPolicy,
    RuntimeIdentity,
    ServicePrincipal,
    ServicePrincipalRegistry,
)
from .platform_admin import (
    PolicyApproval,
    PolicyChangeManager,
    PolicyChangeProposal,
    TrustChangeManager,
    TrustChangeRequest,
)
from .policy import (
    DeterministicArbiter,
    Policy,
    PolicyRegistry,
    SignedPolicyManifest,
    signed_policy_manifest_from_dict,
)
from .replay import ReplayLog, SQLiteReplayLog
from .service import GovernedService
from .signing import KMSSigner, LocalEd25519Signer, RemoteSigner, Signer
from .storage import (
    POSTGRES_NONCE_SCHEMA,
    POSTGRES_REPLAY_SCHEMA,
    NonceRepository,
    PostgresNonceRepository,
    PostgresReplayLog,
    PostgresTrustStore,
    SQLiteNonceRepository,
)
from .trust import TrustStore

# Expose the full substrate API surface: high-level integration entry points plus the
# storage/runtime adapters that deployment code and the existing test suite depend on.
__all__ = [
    # Core Engine & Arbitration
    "ExecutionBoundary",
    "DeterministicArbiter",
    "AuthorizationIssuer",
    "PolicyRegistry",
    "Policy",
    "SignedPolicyManifest",
    "signed_policy_manifest_from_dict",
    "GovernanceRule",
    "GovernanceRuleTranslator",

    # Platform & Mesh
    "GovernancePlatform",
    "PlatformDeploymentPolicy",
    "GovernanceMesh",
    "GovernanceInput",
    "GovernancePreflightDecision",
    "GovernanceSourceRegistry",
    "GovernedService",
    "ServicePrincipal",
    "ServicePrincipalRegistry",
    "RuntimeIdentity",
    "PolicyApproval",
    "PolicyChangeManager",
    "PolicyChangeProposal",
    "TrustChangeManager",
    "TrustChangeRequest",
    "OperatorAPIKey",
    "OperatorKeyStore",

    # Security, Identity & Trust
    "TrustStore",
    "KeyPair",
    "verify_signature",
    "KMSSigner",
    "LocalEd25519Signer",
    "RemoteSigner",
    "Signer",
    "ExternalIdentity",
    "IdentityValidationError",
    "JWKSProvider",
    "JWTValidator",
    "OIDCDiscoveryDocument",
    "OIDCValidator",
    "StaticJWKSProvider",
    "UrlJWKSProvider",
    "discover_oidc_configuration",
    "oidc_validator_from_discovery",

    # Compliance & Audit
    "ComplianceAuditor",
    "ComplianceEvaluation",
    "ReplayLog",
    "SQLiteReplayLog",
    "GovernanceAuthorizationArtifact",
    "SignedApproval",
    "health_report",

    # Federation & Agent Integrations
    "GovernanceReconciler",
    "GovernanceSyncEnvelope",
    "ReconciliationResult",
    "RegistrySnapshot",
    "SignedSyncEvent",
    "A2AGuard",
    "A2ATaskDelegation",
    "GASMCPGateway",
    "GASMCPServer",
    "MCPGatewayContext",
    "MCPToolDefinition",
    "MCPToolResult",
    "GASExecutionBarrierTool",
    "GASCallbackHandler",
    "GASToolOutput",

    # Runtime bootstrap, HTTP API, and job/storage adapters
    "build_demo_service",
    "build_platform_demo",
    "build_runtime_service",
    "AuthenticatedAPI",
    "create_server",
    "parse_server_args",
    "Job",
    "SQLiteJobStore",
    "run_once",
    "NonceRepository",
    "SQLiteNonceRepository",
    "PostgresNonceRepository",
    "POSTGRES_NONCE_SCHEMA",
    "PostgresReplayLog",
    "PostgresTrustStore",
    "POSTGRES_REPLAY_SCHEMA",
    "BoundedRateLimiter",
    "TLSConfig",
    "correlation_id",
    "security_headers",
    "validate_server_config",

    # Core Exceptions
    "AuthorizationError",
    "PolicyDeniedError",
    "GovernanceMeshError",
    "FederationError",
]
