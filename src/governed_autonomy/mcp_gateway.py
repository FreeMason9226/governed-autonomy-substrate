"""
GAS MCP Gateway — governed execution barrier for Model Context Protocol tool calls.

This module bridges the Model Context Protocol (MCP) into the GAS execution
barrier. Every tool call is transparently authorized through a signed GAA before
the underlying handler runs. The GAA nonce, replay frame, and policy decision
are recorded in the append-only audit log.

Usage (without the ``mcp`` package)::

    from governed_autonomy.crypto import KeyPair
    from governed_autonomy.replay import SQLiteReplayLog
    from governed_autonomy.trust import TrustStore
    from governed_autonomy.mcp_gateway import GASMCPGateway, MCPToolDefinition

    key = KeyPair.generate("gateway-issuer-1")
    trust = TrustStore()
    trust.add(key.key_id, key.public_key)
    log = SQLiteReplayLog("gateway.db")

    gateway = GASMCPGateway.create(
        issuer_key=key,
        trust_store=trust,
        replay_log=log,
    )

    @gateway.tool(description="Append text to a file")
    def append_file(request: dict) -> str:
        path = request["path"]
        content = request["content"]
        with open(path, "a") as f:
            f.write(content)
        return f"written {len(content)} bytes to {path}"

    # Serve through MCP SDK:
    #   from governed_autonomy.mcp_gateway import GASMCPServer
    #   server = GASMCPServer(gateway, name="governed-tools")
    #   server.run()

    # Or call directly (e.g. in tests):
    result = gateway.call("append_file", {"path": "/tmp/out.txt", "content": "hello"})
    print(result.content)
    print(result.gaa.nonce)
"""

from __future__ import annotations

import functools
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .crypto import KeyPair
from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .issuer import AuthorizationIssuer, PolicyDeniedError
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .policy import DeterministicArbiter, Policy, PolicyRegistry
from .replay import ReplayLog
from .trust import TrustStore

# ---------------------------------------------------------------------------
# Public data types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MCPToolDefinition:
    """Metadata for a governed MCP tool."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)
    required_fields: tuple[str, ...] = ()
    required_approvals: int = 0


@dataclass(frozen=True)
class MCPToolResult:
    """
    Result of a governed MCP tool call.

    Mirrors the MCP ``CallToolResult`` shape so callers can forward it
    directly to an MCP SDK response without wrapping.
    """

    content: Any
    """The raw return value from the tool handler."""

    gaa: GovernanceAuthorizationArtifact
    """The signed GAA that authorized this execution."""

    tool_name: str
    """Name of the tool that was invoked."""

    is_error: bool = False
    """True only if the handler raised an exception that was caught."""

    def to_mcp_content(self) -> list[dict[str, Any]]:
        """
        Serialize as a list of MCP content items.

        Returns a ``text`` item with the string representation of the result,
        plus a ``text`` item carrying the compact GAA JSON for auditability.
        """
        items: list[dict[str, Any]] = []
        if self.content is not None:
            items.append({"type": "text", "text": str(self.content)})
        items.append(
            {
                "type": "text",
                "text": f"[GAS-GAA] nonce={self.gaa.nonce} "
                f"policy={self.gaa.decision.get('policy')} "
                f"expires={self.gaa.expires_at}",
            }
        )
        return items


@dataclass
class MCPGatewayContext:
    """
    Per-call context injected into action requests before authorization.

    Fields present here are merged into the GAS ``action_request`` under the
    ``context`` key, so policies can require ``tenant_id``, ``agent_id``, etc.
    """

    agent_id: str | None = None
    tenant_id: str | None = None
    session_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ctx: dict[str, Any] = {}
        if self.agent_id is not None:
            ctx["agent_id"] = self.agent_id
        if self.tenant_id is not None:
            ctx["tenant_id"] = self.tenant_id
        if self.session_id is not None:
            ctx["session_id"] = self.session_id
        ctx.update(self.extra)
        return ctx


# ---------------------------------------------------------------------------
# Gateway implementation
# ---------------------------------------------------------------------------

_GATEWAY_POLICY_ID = "gas-mcp-gateway"
_DEFAULT_TTL = 60  # seconds — short-lived by design for MCP calls


class GASMCPGateway:
    """
    Governed execution barrier for MCP tool calls.

    Every call to :meth:`call` follows this invariant:

    1. Build an action request from the tool name + arguments + context.
    2. Arbitrate the request against the gateway policy.
    3. Issue a signed GAA (fails closed if the policy denies).
    4. Claim the nonce atomically and invoke the handler.
    5. Record the execution outcome in the append-only replay log.
    6. Return an :class:`MCPToolResult` with the result and the GAA.

    The gateway is designed to be a drop-in authorization layer for any
    MCP server. It does not require the ``mcp`` package; that dependency
    is only needed by :class:`GASMCPServer`.
    """

    def __init__(
        self,
        *,
        issuer: AuthorizationIssuer,
        boundary: ExecutionBoundary,
        policy_registry: PolicyRegistry,
        ttl_seconds: int = _DEFAULT_TTL,
    ) -> None:
        self._issuer = issuer
        self._boundary = boundary
        self._policy_registry = policy_registry
        self._ttl_seconds = ttl_seconds
        self._handlers: dict[str, Callable[[dict[str, Any]], Any]] = {}
        self._tool_defs: dict[str, MCPToolDefinition] = {}

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        *,
        issuer_key: KeyPair,
        trust_store: TrustStore,
        replay_log: ReplayLog,
        ttl_seconds: int = _DEFAULT_TTL,
        extra_allowed_actions: Sequence[str] = (),
        max_request_bytes: int = 64 * 1024,
        max_ttl_seconds: int = 300,
    ) -> GASMCPGateway:
        """
        Construct a gateway from raw credentials.

        The gateway starts with no registered tools. Register tools via
        :meth:`register_tool` or the :meth:`tool` decorator, then call
        :meth:`rebuild_policy` to update the gateway policy before serving.
        """
        arbiter = DeterministicArbiter(trust_store=trust_store)
        issuer = AuthorizationIssuer(
            issuer=issuer_key,
            replay_log=replay_log,
            arbiter=arbiter,
        )
        # Placeholder policy — rebuilt when tools are registered.
        policy = Policy(
            policy_id=_GATEWAY_POLICY_ID,
            allowed_actions=tuple(sorted(extra_allowed_actions)) or ("__placeholder__",),
            required_fields={},
            exact_fields={},
            max_request_bytes=max_request_bytes,
            max_ttl_seconds=max_ttl_seconds,
        )
        registry = PolicyRegistry((policy,))
        boundary = ExecutionBoundary(
            replay_log=replay_log,
            trust_store=trust_store,
            policy_registry=registry,
            arbiter=arbiter,
        )
        return cls(
            issuer=issuer,
            boundary=boundary,
            policy_registry=registry,
            ttl_seconds=ttl_seconds,
        )

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def register_tool(
        self,
        definition: MCPToolDefinition,
        handler: Callable[[dict[str, Any]], Any],
    ) -> None:
        """
        Register a tool handler and rebuild the gateway policy.

        :param definition: Metadata for the tool, including name, description,
            required fields, and approval requirements.
        :param handler: A callable that accepts the full action request dict
            (including ``"action"`` and ``"context"`` keys) and returns any
            JSON-serializable value.
        :raises ValueError: If a tool with the same name is already registered.
        """
        if definition.name in self._handlers:
            raise ValueError(f"tool already registered: {definition.name!r}")
        self._handlers[definition.name] = handler
        self._tool_defs[definition.name] = definition
        self._rebuild_policy()

    def tool(
        self,
        *,
        description: str,
        input_schema: dict[str, Any] | None = None,
        required_fields: tuple[str, ...] = (),
        required_approvals: int = 0,
    ) -> Callable[[Callable[[dict[str, Any]], Any]], Callable[[dict[str, Any]], Any]]:
        """
        Decorator to register a function as a governed MCP tool.

        The function name becomes the tool name (and GAS action name)::

            @gateway.tool(description="Read a file from disk")
            def read_file(request: dict) -> str:
                return open(request["path"]).read()
        """

        def decorator(
            fn: Callable[[dict[str, Any]], Any],
        ) -> Callable[[dict[str, Any]], Any]:
            defn = MCPToolDefinition(
                name=fn.__name__,
                description=description,
                input_schema=input_schema or {},
                required_fields=required_fields,
                required_approvals=required_approvals,
            )
            self.register_tool(defn, fn)

            @functools.wraps(fn)
            def wrapper(request: dict[str, Any]) -> Any:
                return fn(request)

            return wrapper

        return decorator

    def _rebuild_policy(self) -> None:
        """Reconstruct the gateway policy to reflect all currently registered tools."""
        tool_names = tuple(sorted(self._handlers))
        if not tool_names:
            return
        required_fields = {
            name: defn.required_fields
            for name, defn in self._tool_defs.items()
            if defn.required_fields
        }
        required_approvals = {
            name: defn.required_approvals
            for name, defn in self._tool_defs.items()
            if defn.required_approvals > 0
        }
        existing = self._policy_registry.get(_GATEWAY_POLICY_ID)
        max_bytes = existing.max_request_bytes if existing is not None else 64 * 1024
        max_ttl = existing.max_ttl_seconds if existing is not None else 300
        new_policy = Policy(
            policy_id=_GATEWAY_POLICY_ID,
            allowed_actions=tool_names,
            required_fields=required_fields,
            exact_fields={},
            required_approvals=required_approvals,
            max_request_bytes=max_bytes,
            max_ttl_seconds=max_ttl,
        )
        # Replace the registry with the updated policy.
        self._policy_registry = PolicyRegistry((new_policy,))
        # Re-wire boundary with the new registry.
        self._boundary = ExecutionBoundary(
            replay_log=self._boundary.replay_log,
            trust_store=self._boundary.trust_store,
            policy_registry=self._policy_registry,
            arbiter=self._boundary.arbiter,
        )

    # ------------------------------------------------------------------
    # Core call path
    # ------------------------------------------------------------------

    def call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        *,
        context: MCPGatewayContext | dict[str, Any] | None = None,
        approvals: Sequence[SignedApproval | dict[str, Any]] | None = None,
    ) -> MCPToolResult:
        """
        Authorize and execute a governed MCP tool call.

        :param tool_name: MCP tool name. Must match a registered tool.
        :param arguments: The raw arguments dict from the MCP call.
        :param context: Optional per-call context (agent ID, tenant, session).
        :param approvals: Optional signed approvals for quorum-gated tools.
        :returns: :class:`MCPToolResult` containing the result and the GAA.
        :raises AuthorizationError: If the barrier rejects the call.
        :raises PolicyDeniedError: If the policy denies the request.
        :raises KeyError: If the tool is not registered.
        """
        if tool_name not in self._handlers:
            raise KeyError(f"unknown tool: {tool_name!r}")

        if isinstance(context, MCPGatewayContext):
            ctx_dict = context.to_dict()
        elif isinstance(context, dict):
            ctx_dict = dict(context)
        else:
            # pyrefly: ignore [implicit-any-empty-container]
            ctx_dict = {}

        request: dict[str, Any] = {
            "action": tool_name,
            **arguments,
            "context": ctx_dict,
        }

        policy = self._policy_registry.get(_GATEWAY_POLICY_ID)
        if policy is None:
            raise AuthorizationError("gateway policy is not configured")

        gaa = self._issuer.authorize(
            request,
            policy,
            ttl_seconds=min(self._ttl_seconds, policy.max_ttl_seconds),
            approvals=approvals,
        )

        handler = self._handlers[tool_name]
        result = self._boundary.execute(gaa, handler)

        return MCPToolResult(
            content=result,
            gaa=gaa,
            tool_name=tool_name,
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def list_tools(self) -> tuple[MCPToolDefinition, ...]:
        """Return all registered tool definitions."""
        return tuple(self._tool_defs[name] for name in sorted(self._tool_defs))

    def audit_report(self) -> dict[str, Any]:
        """Return a deterministic audit snapshot of the gateway."""
        return {
            "tools": [
                {
                    "name": defn.name,
                    "description": defn.description,
                    "required_fields": list(defn.required_fields),
                    "required_approvals": defn.required_approvals,
                }
                for defn in self.list_tools()
            ],
            "policy_digest": self._policy_registry.digests().get(_GATEWAY_POLICY_ID),
            "audit_summary": self._boundary.replay_log.audit_summary(),
        }


# ---------------------------------------------------------------------------
# Optional MCP SDK adapter
# ---------------------------------------------------------------------------


class GASMCPServer:
    """
    Thin adapter that exposes a :class:`GASMCPGateway` as an MCP server.

    Requires the ``mcp`` package (``pip install mcp``). Import this class
    only when you need the full MCP server runtime; the rest of the module
    works without any MCP dependency.

    Example::

        server = GASMCPServer(gateway, name="governed-tools")
        server.run()          # stdio transport (default MCP)
    """

    def __init__(self, gateway: GASMCPGateway, *, name: str = "gas-gateway") -> None:
        try:
            # pyrefly: ignore [missing-import]
            import mcp.server as _mcp_server
            # pyrefly: ignore [missing-import]
            import mcp.server.stdio as _mcp_stdio
            # pyrefly: ignore [missing-import]
            import mcp.types as _mcp_types
        except ImportError as exc:
            raise ImportError(
                "GASMCPServer requires the 'mcp' package. "
                "Install it with: pip install mcp"
            ) from exc

        self._gateway = gateway
        self._mcp_server = _mcp_server
        self._mcp_stdio = _mcp_stdio
        self._mcp_types = _mcp_types
        self._server = _mcp_server.Server(name)
        self._name = name
        self._register_handlers()

    def _register_handlers(self) -> None:
        mcp_types = self._mcp_types
        gateway = self._gateway

        @self._server.list_tools()
        async def list_tools() -> list[Any]:
            return [
                mcp_types.Tool(
                    name=defn.name,
                    description=defn.description,
                    inputSchema=defn.input_schema or {
                        "type": "object",
                        "properties": {},
                    },
                )
                for defn in gateway.list_tools()
            ]

        @self._server.call_tool()
        async def call_tool(
            name: str, arguments: dict[str, Any] | None
        ) -> list[Any]:
            args = arguments or {}
            try:
                result = gateway.call(name, args)
                return result.to_mcp_content()
            except (AuthorizationError, PolicyDeniedError, KeyError) as exc:
                return [
                    mcp_types.TextContent(
                        type="text",
                        text=f"[GAS-DENIED] {type(exc).__name__}: {exc}",
                    )
                ]

    def run(self) -> None:
        """Start the MCP server using the stdio transport (blocking)."""
        import asyncio

        async def _main() -> None:
            async with self._mcp_stdio.stdio_server() as (read_stream, write_stream):
                await self._server.run(
                    read_stream,
                    write_stream,
                    self._server.create_initialization_options(),
                )

        asyncio.run(_main())
