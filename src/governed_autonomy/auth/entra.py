"""Microsoft Entra ID device authorization through the official MSAL client."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from ..identity import EntraOIDCConfig


class EntraDeviceAuthorizationClient:
    """Acquire Entra access tokens with the OAuth 2.0 device authorization grant."""

    def __init__(
        self,
        config: EntraOIDCConfig,
        *,
        scopes: Sequence[str],
        client_factory: Callable[..., Any] | None = None,
        cache_path: str | Path | None = None,
    ) -> None:
        if not scopes or any(not isinstance(scope, str) or not scope for scope in scopes):
            raise ValueError("at least one non-empty Entra scope is required")
        self.config = config
        self.scopes = tuple(scopes)
        self.client_factory = client_factory
        self.cache_path = Path(cache_path) if cache_path is not None else None

    def acquire_token(
        self,
        *,
        output: Callable[[str], None] = print,
        interactive: bool = True,
    ) -> dict[str, Any]:
        factory = self.client_factory
        token_cache = None
        if factory is None:
            try:
                import msal
            except ImportError as exc:
                raise RuntimeError(
                    "Entra device login requires MSAL; install governed-autonomy-substrate[entra]"
                ) from exc
            factory = msal.PublicClientApplication
            if self.cache_path is not None:
                try:
                    from msal_extensions import PersistedTokenCache
                    from msal_extensions.persistence import build_encrypted_persistence
                except ImportError as exc:
                    raise RuntimeError(
                        "protected Entra token caching requires the entra extra "
                        "(MSAL and msal-extensions)"
                    ) from exc
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                token_cache = PersistedTokenCache(
                    build_encrypted_persistence(str(self.cache_path))
                )
        parameters: dict[str, Any] = {
            "client_id": self.config.client_id,
            "authority": f"https://login.microsoftonline.com/{self.config.tenant_id}",
        }
        if token_cache is not None:
            parameters["token_cache"] = token_cache
        client = factory(**parameters)
        accounts = client.get_accounts()
        if accounts:
            result = client.acquire_token_silent(list(self.scopes), account=accounts[0])
            if isinstance(result, dict) and isinstance(result.get("access_token"), str):
                return result
        if not interactive:
            return {}
        flow = client.initiate_device_flow(scopes=list(self.scopes))
        if not isinstance(flow, dict) or not flow.get("user_code") or not flow.get("device_code"):
            raise RuntimeError("Microsoft Entra did not return a valid device authorization flow")
        message = flow.get("message")
        if isinstance(message, str) and message:
            output(message)
        result = client.acquire_token_by_device_flow(flow)
        if not isinstance(result, dict) or not isinstance(result.get("access_token"), str):
            error = result.get("error_description", result.get("error", "unknown error")) if isinstance(
                result, dict
            ) else "invalid token response"
            raise RuntimeError(f"Microsoft Entra device authorization failed: {error}")
        return result
