"""
GAS LangChain & LangGraph Adapter — governed execution barrier for LangChain agents.

This module provides tools and callback handlers to enforce GAS execution
governance on LangChain chains, agents, and LangGraph state graphs.

Features:
- ``GASExecutionBarrierTool``: Drop-in wrapper around any callable or tool.
  Ensures that tool execution requires a signed GAA, claims nonces atomically,
  and records audit frames.
- ``GASCallbackHandler``: Lifecycle listener intercepting ``on_tool_start``,
  ``on_tool_end``, and ``on_tool_error`` for continuous audit and enforcement.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from .engine import ExecutionBoundary
from .errors import AuthorizationError
from .issuer import AuthorizationIssuer, PolicyDeniedError
from .models import GovernanceAuthorizationArtifact, SignedApproval
from .policy import Policy, PolicyRegistry
from .replay import ReplayLog
from .trust import TrustStore

try:
    # pyrefly: ignore [missing-import]
    from langchain_core.callbacks import BaseCallbackHandler as _BaseCallbackHandler
except ImportError:  # pragma: no cover
    # Standalone duck-typed fallback when langchain-core is not installed.
    class _BaseCallbackHandler:  # type: ignore[no-redef]
        pass


@dataclass(frozen=True)
class GASToolOutput:
    """Encapsulates the result of a governed LangChain tool call and its GAA."""

    content: Any
    gaa: GovernanceAuthorizationArtifact
    tool_name: str

    def __str__(self) -> str:
        return str(self.content)


class GASExecutionBarrierTool:
    """
    Governed execution wrapper for LangChain tools.

    Compatible with standard LangChain agent loops, tool-calling LLMs,
    and LangGraph tool executor nodes.
    """

    def __init__(
        self,
        func: Callable[..., Any],
        *,
        name: str,
        description: str,
        issuer: AuthorizationIssuer,
        boundary: ExecutionBoundary,
        policy: Policy,
        context: dict[str, Any] | None = None,
        ttl_seconds: int = 60,
    ) -> None:
        self.func = func
        self.name = name
        self.description = description
        self.issuer = issuer
        self.boundary = boundary
        self.policy = policy
        self.context = context or {}
        self.ttl_seconds = ttl_seconds
        functools.update_wrapper(self, func)

    def _normalize_input(self, tool_input: Any) -> dict[str, Any]:
        if isinstance(tool_input, dict):
            return dict(tool_input)
        if isinstance(tool_input, str):
            try:
                parsed = json.loads(tool_input)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                pass
            return {"input": tool_input}
        return {"input": tool_input}

    def run(
        self,
        tool_input: Any,
        *,
        context: dict[str, Any] | None = None,
        approvals: Sequence[SignedApproval | dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> GASToolOutput:
        """Execute the tool under the governance barrier."""
        args_dict = self._normalize_input(tool_input)
        merged_context = {**self.context, **(context or {})}

        request: dict[str, Any] = {
            "action": self.name,
            **args_dict,
            "context": merged_context,
        }

        # 1. Authorize via GAS issuer
        gaa = self.issuer.authorize(
            request,
            self.policy,
            ttl_seconds=min(self.ttl_seconds, self.policy.max_ttl_seconds),
            approvals=approvals,
        )

        # 2. Execute within the execution boundary
        def _callable(req: dict[str, Any]) -> Any:
            # Pass original arguments to underlying function
            if args_dict:
                try:
                    return self.func(**args_dict)
                except TypeError:
                    return self.func(req)
            return self.func()

        raw_result = self.boundary.execute(gaa, _callable)

        return GASToolOutput(
            content=raw_result,
            gaa=gaa,
            tool_name=self.name,
        )

    def invoke(self, tool_input: Any, config: dict[str, Any] | None = None) -> GASToolOutput:
        """LangChain standard Runnable / Tool invocation entrypoint."""
        return self.run(tool_input)

    def __call__(self, *args: Any, **kwargs: Any) -> GASToolOutput:
        if args and not kwargs:
            return self.run(args[0])
        return self.run(kwargs)


# pyrefly: ignore [invalid-inheritance]
class GASCallbackHandler(_BaseCallbackHandler):
    """
    LangChain callback handler that records tool activity in the GAS replay log.

    Captures tool starts, tool ends, and tool exceptions.
    """

    def __init__(
        self,
        replay_log: ReplayLog,
        *,
        session_id: str | None = None,
    ) -> None:
        self.replay_log = replay_log
        self.session_id = session_id
        self._active_spans: dict[str, dict[str, Any]] = {}

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts execution."""
        tool_name = serialized.get("name", "unknown_tool")
        span_key = str(run_id or tool_name)
        event_payload = {
            "type": "langchain_tool_start",
            "tool_name": tool_name,
            "input": input_str,
            "session_id": self.session_id,
        }
        frame_id = f"langchain-start-{span_key[:16]}"
        self.replay_log.append(frame_id, event_payload)
        self._active_spans[span_key] = event_payload

    def on_tool_end(
        self,
        output: Any,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes execution."""
        span_key = str(run_id or "default")
        event_payload = {
            "type": "langchain_tool_end",
            "run_id": span_key,
            "output": str(output)[:500],
            "session_id": self.session_id,
        }
        frame_id = f"langchain-end-{span_key[:16]}"
        self.replay_log.append(frame_id, event_payload)
        self._active_spans.pop(span_key, None)

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: Any = None,
        parent_run_id: Any = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool throws an error."""
        span_key = str(run_id or "default")
        event_payload = {
            "type": "langchain_tool_error",
            "run_id": span_key,
            "error": str(error),
            "error_type": type(error).__name__,
            "session_id": self.session_id,
        }
        frame_id = f"langchain-err-{span_key[:16]}"
        self.replay_log.append(frame_id, event_payload)
        self._active_spans.pop(span_key, None)
