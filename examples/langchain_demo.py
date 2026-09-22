"""
GAS Ecosystem Demo: LangChain & LangGraph Governed Execution.

Demonstrates:
- Creating a GASExecutionBarrierTool.
- Invoking the tool through the LangChain standard interface.
- Catching policy denials.
- Logging lifecycle spans with GASCallbackHandler.
"""

from governed_autonomy import (
    AuthorizationIssuer,
    ExecutionBoundary,
    GASCallbackHandler,
    GASExecutionBarrierTool,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
)
from governed_autonomy.issuer import PolicyDeniedError


def main() -> None:
    print("=== GAS LangChain & LangGraph Demo ===")

    # 1. Setup governance infrastructure
    issuer_key = KeyPair.generate("langchain-governor")
    trust = TrustStore()
    trust.add(issuer_key.key_id, issuer_key.public_key)
    replay = ReplayLog()

    policy = Policy(
        policy_id="enterprise-tools-v1",
        allowed_actions=("send_notification",),
        required_fields={"send_notification": ("recipient", "message")},
        exact_fields={},
        max_request_bytes=64 * 1024,
        max_ttl_seconds=300,
    )
    registry = PolicyRegistry((policy,))
    issuer = AuthorizationIssuer(issuer=issuer_key, replay_log=replay)
    boundary = ExecutionBoundary(replay_log=replay, trust_store=trust, policy_registry=registry)

    # 2. Define business logic function
    def send_notification(recipient: str, message: str) -> str:
        return f"Notification delivered to {recipient}: '{message}'"

    # 3. Wrap function with GAS Execution Barrier
    governed_tool = GASExecutionBarrierTool(
        send_notification,
        name="send_notification",
        description="Deliver a user notification",
        issuer=issuer,
        boundary=boundary,
        policy=policy,
    )

    # 4. Attach callback handler to record lifecycle
    callback = GASCallbackHandler(replay_log=replay, session_id="session-demo-01")

    callback.on_tool_start(
        {"name": "send_notification"},
        input_str='{"recipient": "admin@example.com", "message": "High CPU load"}',
        run_id="run-42",
    )

    # 5. Execute tool via .invoke()
    result = governed_tool.invoke({
        "recipient": "admin@example.com",
        "message": "High CPU load",
    })

    callback.on_tool_end(result.content, run_id="run-42")

    print("\n--- Successful Governed Execution ---")
    print(f"Tool Output:      {result.content}")
    print(f"GAA Nonce:        {result.gaa.nonce}")
    print(f"GAA Policy:       {result.gaa.decision['policy']}")

    # 6. Test Policy Denial (e.g. missing required field 'message')
    print("\n--- Testing Policy Denial ---")
    try:
        governed_tool.invoke({"recipient": "admin@example.com"})
    except PolicyDeniedError as e:
        print(f"Correctly Denied by Policy: {e}")

    # 7. Audit Log Summary
    summary = replay.audit_summary()
    print(f"\nAudit Log Total Frames: {summary['frame_count']} (Chain Verified: {replay.verify_chain()})")


if __name__ == "__main__":
    main()
