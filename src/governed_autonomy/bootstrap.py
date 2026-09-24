import os
import json
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import b64decode, b64encode
from .crypto import KeyPair
from .engine import ExecutionBoundary
from .issuer import AuthorizationIssuer
from .platform import GovernancePlatform, RuntimeIdentity
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog
from .service import GovernedService
from .storage import PostgresReplayLog, PostgresTrustStore
from .trust import TrustStore
from .governance_service import GovernanceService
from .signing import KMSHSMBackedSigner


def build_demo_service() -> tuple[GovernedService, KeyPair, ReplayLog]:
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
        actions={"write_file": lambda request: request["content"]},
    )
    return service, issuer, replay_log


def build_runtime_service() -> tuple[GovernedService, KeyPair, ReplayLog]:
    """Build the server composition from explicit production environment settings."""
    mode = os.environ.get("GAS_RUNTIME_MODE", "postgres").lower()
    if mode == "memory":
        return build_demo_service()
    if mode != "postgres":
        raise ValueError("GAS_RUNTIME_MODE must be postgres or memory")

    database_url = os.environ.get("DATABASE_URL")
    key_id = os.environ.get("GAS_ISSUER_KEY_ID")
    kms_endpoint = os.environ.get("GAS_KMS_SIGN_ENDPOINT")
    public_key = os.environ.get("GAS_ISSUER_PUBLIC_KEY")
    kms_token = os.environ.get("GAS_KMS_SIGN_TOKEN")
    if not all((database_url, key_id, kms_endpoint, public_key, kms_token)):
        raise RuntimeError(
            "DATABASE_URL, GAS_ISSUER_KEY_ID, GAS_KMS_SIGN_ENDPOINT, "
            "GAS_ISSUER_PUBLIC_KEY, and GAS_KMS_SIGN_TOKEN "
            "are required in postgres runtime mode"
        )
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("install the postgres extra to use postgres runtime mode") from exc

    public_key_bytes = b64decode(public_key)
    Ed25519PublicKey.from_public_bytes(public_key_bytes)

    def kms_sign(payload: bytes) -> bytes:
        request = urllib.request.Request(
            kms_endpoint,
            data=json.dumps({"key_id": key_id, "payload": b64encode(payload)}).encode(),
            headers={
                "Authorization": f"Bearer {kms_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.loads(response.read().decode("utf-8"))
        return b64decode(result["signature"])

    issuer = KMSHSMBackedSigner(key_id, kms_sign, public_key_bytes)
    replay_log = PostgresReplayLog(psycopg.connect(database_url))
    trust_store = PostgresTrustStore(replay_log.connection)
    if trust_store.resolve(issuer.key_id) is None:
        trust_store.add(issuer.key_id, Ed25519PublicKey.from_public_bytes(public_key_bytes))
    policy_registry = PolicyRegistry(
        (
            Policy(
                "demo-files-v1",
                ("write_file",),
                {"write_file": ("path", "content")},
                {"write_file": {"path": "out.txt"}},
            ),
        )
    )
    service = GovernedService(
        issuer=AuthorizationIssuer(
            governance_service=GovernanceService(
                signer=issuer,
                replay_log=replay_log,
                attestor=KeyPair.generate("governance-attestor"),
            )
        ),
        boundary=ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=policy_registry,
        ),
        policies=policy_registry,
        actions={"write_file": lambda request: request["content"]},
    )
    return service, issuer, replay_log


def build_platform_demo(
    *,
    service_name: str = "governed-file-api",
    environment: str = "prod",
    tenant_id: str | None = None,
    actor_id: str | None = None,
) -> tuple[GovernancePlatform, GovernedService, KeyPair, ReplayLog]:
    """Build a platform-ready composition with runtime identity and runtime metadata."""
    service, issuer, replay_log = build_demo_service()
    platform = GovernancePlatform(
        service=service,
        identity=RuntimeIdentity(
            service=service_name,
            environment=environment,
            tenant_id=tenant_id,
            actor_id=actor_id,
        ),
    )
    return platform, service, issuer, replay_log
