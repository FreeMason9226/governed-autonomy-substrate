"""Governed Autonomy Substrate MVP."""

from .a2a import A2AGuard, A2ATaskDelegation
from .compliance import ComplianceAuditor, ComplianceEvaluation
from .crypto import KeyPair, verify_signature
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
from .identity import (
    ExternalIdentity,
    IdentityValidationError,
    JWKSProvider,
    JWTValidator,
    OIDCValidator,
)
from .issuer import AuthorizationIssuer, PolicyDeniedError
from .langchain_adapter import GASExecutionBarrierTool
from .mcp_gateway import GASMCPGateway, GASMCPServer
from .mesh import (
    GovernanceInput,
    GovernanceMesh,
    GovernanceMeshError,
    GovernancePreflightDecision,
    GovernanceSourceRegistry,
)
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .platform import (
    GovernancePlatform,
    PlatformDeploymentPolicy,
    RuntimeIdentity,
    ServicePrincipal,
    ServicePrincipalRegistry,
)
from .policy import (
    DeterministicArbiter,
    Policy,
    PolicyRegistry,
    SignedPolicyManifest,
)
from .replay import ReplayLog
from .service import GovernedService
from .signing import KMSSigner, Signer
from .trust import TrustStore

# Expose only the high-level API surface required for substrate integration.
# Storage implementations and internal schemas remain private to enforce strict architectural boundaries.
__all__ = [
    # Core Engine & Arbitration
    "ExecutionBoundary",
    "DeterministicArbiter",
    "AuthorizationIssuer",
    "PolicyRegistry",
    "Policy",
    "SignedPolicyManifest",
    "GovernanceRule",
    
    # Platform & Mesh
    "GovernancePlatform",
    "GovernanceMesh",
    "GovernedService",
    "ServicePrincipal",
    "RuntimeIdentity",
    
    # Security, Identity & Trust
    "TrustStore",
    "KMSSigner",
    "Signer",
    "ExternalIdentity",
    "JWKSProvider",
    "OIDCValidator",
    
    # Compliance & Audit
    "ComplianceAuditor",
    "ReplayLog",
    "GovernanceAuthorizationArtifact",
    "SignedApproval",
    
    # Federation & Agent Integrations
    "GovernanceReconciler",
    "RegistrySnapshot",
    "A2AGuard",
    "GASMCPGateway",
    "GASExecutionBarrierTool",
    
    # Core Exceptions
    "AuthorizationError",
    "PolicyDeniedError",
    "GovernanceMeshError",
    "FederationError",
]
