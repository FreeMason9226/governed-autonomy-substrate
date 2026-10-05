"""Enterprise identity adapters and authorization primitives."""

from .entra import EntraDeviceAuthorizationClient
from .jwt_validator import JWTReplayCache, JWTValidator
from .service_identity import ServiceIdentity, service_identity_from_claims

__all__ = [
    "EntraDeviceAuthorizationClient",
    "JWTReplayCache",
    "JWTValidator",
    "ServiceIdentity",
    "service_identity_from_claims",
]
