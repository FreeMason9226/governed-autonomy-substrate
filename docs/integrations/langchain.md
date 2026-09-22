# LangChain & LangGraph Integration

## Overview

The **GAS LangChain Adapter** provides drop-in tools and callback handlers to govern tool invocations and state changes in **LangChain** and **LangGraph** agent workflows.

Traditional LangChain agents directly call tools and apply side effects when an LLM produces a tool call. With the GAS adapter:

- The tool cannot run without a valid, cryptographically signed **Governance Authorization Artifact (GAA)**.
- Every invocation claims a single-use nonce atomically in the append-only replay log, enforcing **at-most-once execution** even if the agent loops or retries.
- Multi-party approval quorums can be required for high-risk tools.
- Complete lifecycle telemetry (`on_tool_start`, `on_tool_end`, `on_tool_error`) is committed to the hash-chained audit log.

---

## Using `GASExecutionBarrierTool`

`GASExecutionBarrierTool` wraps any Python function or existing LangChain tool into a governed execution barrier:

```python
from governed_autonomy import (
    AuthorizationIssuer,
    ExecutionBoundary,
    KeyPair,
    Policy,
    PolicyRegistry,
    ReplayLog,
    TrustStore,
)
from governed_autonomy.langchain_adapter import GASExecutionBarrierTool

# 1. Setup governance credentials and policies
issuer_key = KeyPair.generate("langchain-governor")
trust = TrustStore()
trust.add(issuer_key.key_id, issuer_key.public_key)
replay = ReplayLog()

policy = Policy(
    policy_id="agent-policy-v1",
    allowed_actions=("read_doc", "send_email"),
    required_fields={"send_email": ("recipient", "body")},
    exact_fields={},
    max_request_bytes=64 * 1024,
    max_ttl_seconds=300,
)
registry = PolicyRegistry((policy,))
boundary = ExecutionBoundary(replay_log=replay, trust_store=trust, policy_registry=registry)
issuer = AuthorizationIssuer(issuer=issuer_key, replay_log=replay)

# 2. Define the tool
def send_email(recipient: str, body: str) -> str:
    # Action with external side effect
    return f"Email sent to {recipient}"

governed_tool = GASExecutionBarrierTool(
    send_email,
    name="send_email",
    description="Send an email to a recipient",
    issuer=issuer,
    boundary=boundary,
    policy=policy,
)

# 3. Use in LangChain agents or invoke directly
result = governed_tool.invoke({"recipient": "alice@example.com", "body": "Quarterly report"})
print("Output:", result.content)
print("Bound GAA Nonce:", result.gaa.nonce)
```

---

## Intercepting LangGraph Graphs with `GASCallbackHandler`

To audit and trace tools across a multi-agent graph or LangGraph state machine:

```python
from governed_autonomy.langchain_adapter import GASCallbackHandler

handler = GASCallbackHandler(replay_log=replay, session_id="agent-run-8821")

# Attach to LangChain agent or chain config
# response = agent_executor.invoke({"input": "..."}, config={"callbacks": [handler]})
```

All tool activations, arguments, outputs, and errors will be hashed and sequenced into the immutable replay chain.
