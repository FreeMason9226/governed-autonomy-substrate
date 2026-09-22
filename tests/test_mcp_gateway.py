from __future__ import annotations

import pytest

from governed_autonomy import (
    KeyPair,
    ReplayLog,
    SignedApproval,
    TrustStore,
)
from governed_autonomy.issuer import PolicyDeniedError
from governed_autonomy.mcp_gateway import (
    GASMCPGateway,
    GASMCPServer,
    MCPGatewayContext,
    MCPToolDefinition,
    MCPToolResult,
)


@pytest.fixture
def test_setup() -> tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog]:
    issuer_key = KeyPair.generate("gateway-issuer-1")
    trust = TrustStore()
    trust.add(issuer_key.key_id, issuer_key.public_key)
    replay = ReplayLog()
    gateway = GASMCPGateway.create(
        issuer_key=issuer_key,
        trust_store=trust,
        replay_log=replay,
    )
    return gateway, issuer_key, trust, replay


def test_tool_decorator_and_successful_call(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, issuer_key, trust, replay = test_setup

    @gateway.tool(description="Add two numbers", required_fields=("a", "b"))
    def add(request: dict) -> int:
        return request["a"] + request["b"]

    tools = gateway.list_tools()
    assert len(tools) == 1
    assert tools[0].name == "add"
    assert tools[0].description == "Add two numbers"
    assert tools[0].required_fields == ("a", "b")

    # Call with valid arguments
    result = gateway.call("add", {"a": 10, "b": 25})
    assert isinstance(result, MCPToolResult)
    assert result.content == 35
    assert result.tool_name == "add"
    assert result.is_error is False
    assert result.gaa.nonce
    assert result.gaa.decision["allow"] is True

    # Check to_mcp_content formatting
    content = result.to_mcp_content()
    assert len(content) == 2
    assert content[0]["type"] == "text"
    assert content[0]["text"] == "35"
    assert content[1]["type"] == "text"
    assert "[GAS-GAA]" in content[1]["text"]
    assert f"nonce={result.gaa.nonce}" in content[1]["text"]

    # Replay log verification
    assert replay.verify_chain() is True
    summary = replay.audit_summary()
    assert summary["frame_count"] == 2  # 1 authorization frame + 1 execution frame
    assert summary["execution_count"] == 1
    assert summary["success_count"] == 1


def test_unknown_tool_raises_key_error(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, _, _, _ = test_setup
    with pytest.raises(KeyError, match="unknown tool: 'nonexistent'"):
        gateway.call("nonexistent", {})


def test_duplicate_tool_registration_rejected(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, _, _, _ = test_setup

    gateway.register_tool(
        MCPToolDefinition(name="echo", description="Echo input"),
        lambda req: req.get("text"),
    )
    with pytest.raises(ValueError, match="tool already registered: 'echo'"):
        gateway.register_tool(
            MCPToolDefinition(name="echo", description="Duplicate echo"),
            lambda req: req.get("text"),
        )


def test_missing_required_field_denied(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, _, _, _ = test_setup

    @gateway.tool(description="Write file", required_fields=("path", "content"))
    def write_file(request: dict) -> str:
        return "ok"

    # Call missing "content"
    with pytest.raises(PolicyDeniedError, match="policy denied authorization"):
        gateway.call("write_file", {"path": "/tmp/test.txt"})


def test_approval_quorum_gated_tool(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, issuer_key, trust, _ = test_setup

    approver_key = KeyPair.generate("security-officer")
    trust.add(approver_key.key_id, approver_key.public_key)

    @gateway.tool(
        description="Deploy service",
        required_fields=("service", "env"),
        required_approvals=1,
    )
    def deploy(request: dict) -> str:
        return f"deployed {request['service']} to {request['env']}"

    args = {"service": "payments-api", "env": "prod"}

    # Fails without approval
    with pytest.raises(PolicyDeniedError, match="approval quorum not met"):
        gateway.call("deploy", args)

    # Issue approval
    from governed_autonomy.canonical import canonical_json
    import hashlib

    raw_req = {"action": "deploy", **args, "context": {}}
    req_digest = hashlib.sha256(canonical_json(raw_req)).hexdigest()
    # Dummy decision digest matching what arbiter expects or using SignedApproval.from_request
    approval = SignedApproval.issue(
        action="deploy",
        request_digest=req_digest,
        decision_digest="0" * 64,
        issuer=approver_key,
    )

    # Call with signed approval
    result = gateway.call("deploy", args, approvals=[approval])
    assert result.content == "deployed payments-api to prod"
    assert result.gaa.decision["allow"] is True


def test_context_injection(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, _, _, _ = test_setup

    captured_context: dict = {}

    @gateway.tool(description="Inspect context")
    def inspect_ctx(request: dict) -> str:
        captured_context.update(request.get("context", {}))
        return "done"

    ctx = MCPGatewayContext(agent_id="agent-007", tenant_id="acme-corp", session_id="sess-42")
    res = gateway.call("inspect_ctx", {}, context=ctx)
    assert res.content == "done"
    assert captured_context == {
        "agent_id": "agent-007",
        "tenant_id": "acme-corp",
        "session_id": "sess-42",
    }


def test_audit_report(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, _, _, _ = test_setup

    @gateway.tool(description="Tool A")
    def tool_a(req: dict) -> str:
        return "a"

    report = gateway.audit_report()
    assert "tools" in report
    assert len(report["tools"]) == 1
    assert report["tools"][0]["name"] == "tool_a"
    assert report["policy_digest"] is not None
    assert "audit_summary" in report


def test_gas_mcp_server_import_check(
    test_setup: tuple[GASMCPGateway, KeyPair, TrustStore, ReplayLog],
) -> None:
    gateway, _, _, _ = test_setup
    try:
        import mcp  # noqa: F401
        server = GASMCPServer(gateway, name="test-server")
        assert server is not None
    except ImportError:
        with pytest.raises(ImportError, match="requires the 'mcp' package"):
            GASMCPServer(gateway, name="test-server")
