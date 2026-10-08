import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .crypto import KeyPair
from .engine import ExecutionBoundary
from .issuer import AuthorizationIssuer
from .platform import GovernancePlatform, RuntimeIdentity
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog
from .service import GovernedService
from .signing import KMSSigner, Signer
from .storage import PostgresReplayLog, PostgresTrustStore
from .trust import TrustStore


def _runtime_signer(signer: Signer | None = None) -> Signer:
    if signer is not None:
        return signer
    backend = os.environ.get("GAS_ISSUER_SIGNER", "local").lower()
    if backend == "aws-kms":
        key_id = os.environ.get("GAS_ISSUER_KMS_KEY_ID")
        if not key_id:
            raise RuntimeError("GAS_ISSUER_KMS_KEY_ID is required for the aws-kms signer")
        try:
            from .kms_backends import AwsKmsBackend

            kms_backend = AwsKmsBackend(region_name=os.environ.get("AWS_REGION"))
        except Exception as exc:
            raise RuntimeError("unable to initialize the AWS KMS signer") from exc
        return KMSSigner(key_id, kms_backend)
    if backend != "local":
        raise ValueError("GAS_ISSUER_SIGNER must be local or aws-kms")
    key_id = os.environ.get("GAS_ISSUER_KEY_ID")
    private_key = os.environ.get("GAS_ISSUER_PRIVATE_KEY")
    if not key_id or not private_key:
        raise RuntimeError(
            "GAS_ISSUER_KEY_ID and GAS_ISSUER_PRIVATE_KEY are required for the local signer"
        )
    return KeyPair.from_private_key_b64(key_id, private_key)


def build_demo_service(
    *,
    mesh_source_registry=None,
) -> tuple[GovernedService, KeyPair, ReplayLog]:
    """Build a complete in-process composition for demos and integration tests."""
    issuer = KeyPair.generate("demo-issuer")
    replay_log = ReplayLog()
    trust_store = TrustStore()
    trust_store.add(issuer.key_id, issuer.public_key)
    policy_registry = PolicyRegistry(
        (
            Policy(
                "demo-files-v1",
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            ),
            Policy(
                "demo-jobs-v1",
                ("run_job",),
                {"run_job": ("image", "command")},
                {},
            ),
        )
    )
    service = GovernedService(
        issuer=AuthorizationIssuer(
            issuer=issuer,
            replay_log=replay_log,
            mesh_source_registry=mesh_source_registry,
        ),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=policy_registry,
        ),
        policies=policy_registry,
        actions={
            "write_file": lambda request: request["content"],
            "run_job": lambda request: {
                "image": request["image"],
                "command": request["command"],
            },
        },
        mesh_source_registry=mesh_source_registry,
    )
    return service, issuer, replay_log


def build_runtime_service(
    *,
    signer: Signer | None = None,
) -> tuple[GovernedService, Signer, ReplayLog]:
    """Build the server composition from explicit production environment settings.

    A deployment may inject a remote or KMS-backed signer. When omitted, the
    legacy environment-backed local key path remains available for development
    and controlled deployments.
    """
    mode = os.environ.get("GAS_RUNTIME_MODE", "postgres").lower()
    if mode == "memory":
        return build_demo_service()
    if mode != "postgres":
        raise ValueError("GAS_RUNTIME_MODE must be postgres or memory")

    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is required in postgres runtime mode"
        )
    runtime_signer = _runtime_signer(signer)
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("install the postgres extra to use postgres runtime mode") from exc

    issuer = runtime_signer
    replay_log = PostgresReplayLog(psycopg.connect(database_url))
    trust_store = PostgresTrustStore(replay_log.connection)
    if trust_store.resolve(issuer.key_id) is None:
        trust_store.add(
            issuer.key_id,
            Ed25519PublicKey.from_public_bytes(issuer.public_key_bytes()),
        )
    policy_registry = PolicyRegistry(
        (
            Policy(
                "demo-files-v1",
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            ),
            Policy(
                "demo-jobs-v1",
                ("run_job",),
                {"run_job": ("image", "command")},
                {},
            ),
        )
    )
    service = GovernedService(
        issuer=AuthorizationIssuer(issuer=issuer, replay_log=replay_log),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=policy_registry,
        ),
        policies=policy_registry,
        actions={
            "write_file": lambda request: request["content"],
            "run_job": lambda request: {
                "image": request["image"],
                "command": request["command"],
            },
        },
    )
    return service, issuer, replay_log


def build_platform_demo(
    *,
    service_name: str = "governed-file-api",
    environment: str = "prod",
    tenant_id: str | None = None,
    actor_id: str | None = None,
    mesh_source_registry=None,
) -> tuple[GovernancePlatform, GovernedService, KeyPair, ReplayLog]:
    """Build a platform-ready composition with runtime identity and runtime metadata."""
    service, issuer, replay_log = build_demo_service(mesh_source_registry=mesh_source_registry)
    platform = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(
            service=service_name,
            environment=environment,
            tenant_id=tenant_id,
            actor_id=actor_id,
        ),
        mesh_source_registry=mesh_source_registry,
    )
    return platform, service, issuer, replay_log
