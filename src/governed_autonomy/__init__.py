"""Governed Autonomy Substrate MVP."""

from .crypto import KeyPair
from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .governance import GovernanceRule, GovernanceRuleTranslator
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .policy import (
    DeterministicArbiter,
    Policy,
    PolicyRegistry,
    SignedPolicyManifest,
    signed_policy_manifest_from_dict,
)
from .replay import ReplayLog, SQLiteReplayLog
from .issuer import AuthorizationIssuer, PolicyDeniedError
from .trust import TrustStore
from .service import GovernedService
from .health import health_report
from .bootstrap import build_demo_service, build_platform_demo
from .http_api import AuthenticatedAPI, create_server, parse_server_args
from .platform import (
    GovernancePlatform,
    PlatformDeploymentPolicy,
    RuntimeIdentity,
    ServicePrincipal,
    ServicePrincipalRegistry,
)
from .platform_admin import PolicyApproval, PolicyChangeManager, PolicyChangeProposal
from .identity import ExternalIdentity, IdentityValidationError, JWKSProvider, OIDCValidator, JWTValidator, StaticJWKSProvider
from .signing import LocalEd25519Signer, RemoteSigner, Signer
from .storage import NonceRepository, SQLiteNonceRepository, PostgresNonceRepository, POSTGRES_NONCE_SCHEMA, PostgresReplayLog, POSTGRES_REPLAY_SCHEMA
from .deployment import BoundedRateLimiter, TLSConfig, correlation_id, security_headers, validate_server_config
from .jobs import Job, SQLiteJobStore, run_once
from .mcp_gateway import GASMCPGateway, GASMCPServer, MCPGatewayContext, MCPToolDefinition, MCPToolResult
from .langchain_adapter import GASCallbackHandler, GASExecutionBarrierTool, GASToolOutput
from .a2a import A2AGuard, A2ATaskDelegation
from .compliance import ComplianceAuditor, ComplianceEvaluation

__all__ = [
    "AuthorizationError",
    "AuthorizationIssuer",
    "ExecutionBoundary",
    "GovernanceAuthorizationArtifact",
    "SignedApproval",
    "DeterministicArbiter",
    "GovernanceRule",
    "GovernanceRuleTranslator",
    "KeyPair",
    "Policy",
    "PolicyRegistry",
    "SignedPolicyManifest",
    "signed_policy_manifest_from_dict",
    "PolicyDeniedError",
    "ReplayLog",
    "SQLiteReplayLog",
    "TrustStore",
    "GovernedService",
    "health_report",
    "build_demo_service",
    "build_platform_demo",
    "AuthenticatedAPI",
    "create_server",
    "parse_server_args",
    "GovernancePlatform",
    "PlatformDeploymentPolicy",
    "RuntimeIdentity",
    "ServicePrincipal",
    "ServicePrincipalRegistry",
    "PolicyApproval",
    "PolicyChangeManager",
    "PolicyChangeProposal",
    "ExternalIdentity",
    "IdentityValidationError",
    "JWKSProvider",
    "OIDCValidator",
    "JWTValidator",
    "StaticJWKSProvider",
    "LocalEd25519Signer",
    "RemoteSigner",
    "Signer",
    "NonceRepository",
    "SQLiteNonceRepository",
    "PostgresNonceRepository",
    "POSTGRES_NONCE_SCHEMA",
    "PostgresReplayLog",
    "POSTGRES_REPLAY_SCHEMA",
    "BoundedRateLimiter",
    "TLSConfig",
    "correlation_id",
    "security_headers",
    "validate_server_config",
    "Job",
    "SQLiteJobStore",
    "run_once",
    "GASMCPGateway",
    "GASMCPServer",
    "MCPGatewayContext",
    "MCPToolDefinition",
    "MCPToolResult",
    "GASExecutionBarrierTool",
    "GASCallbackHandler",
    "GASToolOutput",
    "A2ATaskDelegation",
    "A2AGuard",
    "ComplianceAuditor",
    "ComplianceEvaluation",
]
