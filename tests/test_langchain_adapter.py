from __future__ import annotations

import pytest

from governed_autonomy import (
    AuthorizationIssuer,
    ExecutionBoundary,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    SignedApproval,
    TrustStore,
)
from governed_autonomy.issuer import PolicyDeniedError
from governed_autonomy.langchain_adapter import (
    GASCallbackHandler,
    GASExecutionBarrierTool,
    GASToolOutput,
)
from governed_autonomy.policy import DeterministicArbiter


@pytest.fixture
def langchain_setup() -> tuple[AuthorizationIssuer, ExecutionBoundary, Policy, ReplayLog, KeyPair, TrustStore]:
    issuer_key = KeyPair.generate("langchain-issuer")
    trust = TrustStore()
    trust.add(issuer_key.key_id, issuer_key.public_key)
    replay = ReplayLog()

    policy = Policy(
        policy_id="langchain-policy",
        allowed_actions=("calc_tax", "search_web"),
        required_fields={"calc_tax": ("amount",), "search_web": ("query",)},
        exact_fields={},
        max_request_bytes=64 * 1024,
        max_ttl_seconds=300,
        required_approvals={"calc_tax": 1},
    )
    registry = PolicyRegistry((policy,))
    arbiter = DeterministicArbiter(trust_store=trust)

    issuer = AuthorizationIssuer(
        issuer=issuer_key,
        replay_log=replay,
        arbiter=arbiter,
    )
    boundary = ExecutionBoundary(
        replay_log=replay,
        trust_store=trust,
        policy_registry=registry,
        arbiter=arbiter,
    )
    return issuer, boundary, policy, replay, issuer_key, trust


def test_tool_successful_execution(
    langchain_setup: tuple[AuthorizationIssuer, ExecutionBoundary, Policy, ReplayLog, KeyPair, TrustStore],
) -> None:
    issuer, boundary, policy, replay, _, _ = langchain_setup

    def search_web(query: str) -> str:
        return f"results for {query}"

    tool = GASExecutionBarrierTool(
        search_web,
        name="search_web",
        description="Search the web",
        issuer=issuer,
        boundary=boundary,
        policy=policy,
    )

    # 1. Test .run() with dict
    res1 = tool.run({"query": "quantum computing"})
    assert isinstance(res1, GASToolOutput)
    assert res1.content == "results for quantum computing"
    assert str(res1) == "results for quantum computing"
    assert res1.gaa.decision["allow"] is True

    # 2. Test .invoke()
    res2 = tool.invoke({"query": "ai agents"})
    assert res2.content == "results for ai agents"

    # 3. Test __call__()
    res3 = tool({"query": "governance"})
    assert res3.content == "results for governance"

    # Replay log verification
    assert replay.verify_chain() is True
    # 3 tool calls = 3 authorization frames + 3 execution frames = 6 frames
    assert len(replay.frames) == 6


def test_tool_policy_denial_unallowed_action(
    langchain_setup: tuple[AuthorizationIssuer, ExecutionBoundary, Policy, ReplayLog, KeyPair, TrustStore],
) -> None:
    issuer, boundary, policy, _, _, _ = langchain_setup

    def delete_db() -> str:
        return "deleted"

    tool = GASExecutionBarrierTool(
        delete_db,
        name="delete_db",
        description="Delete database",
        issuer=issuer,
        boundary=boundary,
        policy=policy,
    )

    with pytest.raises(PolicyDeniedError, match="policy denied authorization"):
        tool.run({})


def test_tool_policy_denial_missing_field(
    langchain_setup: tuple[AuthorizationIssuer, ExecutionBoundary, Policy, ReplayLog, KeyPair, TrustStore],
) -> None:
    issuer, boundary, policy, _, _, _ = langchain_setup

    def search_web(query: str) -> str:
        return query

    tool = GASExecutionBarrierTool(
        search_web,
        name="search_web",
        description="Search",
        issuer=issuer,
        boundary=boundary,
        policy=policy,
    )

    with pytest.raises(PolicyDeniedError, match="required field is missing: query"):
        tool.run({})


def test_tool_approval_quorum(
    langchain_setup: tuple[AuthorizationIssuer, ExecutionBoundary, Policy, ReplayLog, KeyPair, TrustStore],
) -> None:
    issuer, boundary, policy, _, _, trust = langchain_setup

    approver_key = KeyPair.generate("tax-approver")
    trust.add(approver_key.key_id, approver_key.public_key)

    def calc_tax(amount: float) -> float:
        return amount * 0.2

    tool = GASExecutionBarrierTool(
        calc_tax,
        name="calc_tax",
        description="Calculate tax",
        issuer=issuer,
        boundary=boundary,
        policy=policy,
    )

    # Denied without approval
    with pytest.raises(PolicyDeniedError, match="approval quorum not met"):
        tool.run({"amount": 1000.0})

    # Prepare signed approval
    from governed_autonomy.canonical import canonical_json
    import hashlib

    raw_req = {"action": "calc_tax", "amount": 1000.0, "context": {}}
    req_digest = hashlib.sha256(canonical_json(raw_req)).hexdigest()
    approval = SignedApproval.issue(
        action="calc_tax",
        request_digest=req_digest,
        decision_digest="0" * 64,
        issuer=approver_key,
    )

    res = tool.run({"amount": 1000.0}, approvals=[approval])
    assert res.content == 200.0


def test_callback_handler_lifecycle() -> None:
    replay = ReplayLog()
    handler = GASCallbackHandler(replay, session_id="session-xyz")

    # 1. Start event
    handler.on_tool_start(
        {"name": "fetch_data"},
        input_str='{"id": 1}',
        run_id="run-123",
    )
    assert len(replay.frames) == 1
    assert replay.frames[0].event["type"] == "langchain_tool_start"
    assert replay.frames[0].event["tool_name"] == "fetch_data"
    assert replay.frames[0].event["session_id"] == "session-xyz"

    # 2. End event
    handler.on_tool_end("data retrieved", run_id="run-123")
    assert len(replay.frames) == 2
    assert replay.frames[1].event["type"] == "langchain_tool_end"
    assert replay.frames[1].event["output"] == "data retrieved"

    # 3. Error event
    handler.on_tool_error(ValueError("network error"), run_id="run-456")
    assert len(replay.frames) == 3
    assert replay.frames[2].event["type"] == "langchain_tool_error"
    assert replay.frames[2].event["error_type"] == "ValueError"

    # Verify chain integrity
    assert replay.verify_chain() is True
