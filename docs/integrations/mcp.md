# Model Context Protocol (MCP) Gateway Integration

## Overview

The **GAS MCP Gateway** integrates the Governed Autonomy Substrate directly into the **Model Context Protocol (MCP)** tool execution lifecycle.

In an ungoverned agent deployment, when an LLM issues a `tools/call` request, the MCP server immediately invokes the corresponding function and returns the side-effect output. With the GAS MCP Gateway:

1. Every incoming tool call is transformed into a deterministic action request.
2. The request is evaluated against the registered governance policy.
3. If approved, an authorized issuer produces a cryptographically signed **Governance Authorization Artifact (GAA)** bound to the request and a unique single-use nonce.
4. The execution barrier validates the GAA and atomically claims the nonce, guaranteeing **at-most-once execution**.
5. Both authorization and execution are permanently committed to an append-only hash-chained audit log.
6. The MCP response returns the tool output along with verifiable GAA audit metadata in `content`.

```
[ LLM Agent ] 
     │
     ▼ (tools/call: write_file)
[ GAS MCP Gateway ] ──► [ Deterministic Arbiter ] (evaluate policy)
     │                                 │
     │◄── Signed GAA Token ────────────┘
     ▼
[ Execution Barrier ] (verify signature, claim nonce atomically)
     │
     ├──► [ Append-Only Replay Log ] (record authorization & execution)
     ▼
[ Tool Handler ] (safe execution with side effects)
```

---

## Quickstart

### 1. In-Memory Gateway Setup

You can use the gateway directly without installing the `mcp` package:

```python
from governed_autonomy import KeyPair, ReplayLog, TrustStore
from governed_autonomy.mcp_gateway import GASMCPGateway

# 1. Provision issuer key and trust store
issuer_key = KeyPair.generate("gateway-issuer-1")
trust = TrustStore()
trust.add(issuer_key.key_id, issuer_key.public_key)
replay = ReplayLog()

# 2. Instantiate the gateway
gateway = GASMCPGateway.create(
    issuer_key=issuer_key,
    trust_store=trust,
    replay_log=replay,
)

# 3. Register governed tools
@gateway.tool(description="Read file contents", required_fields=("path",))
def read_file(request: dict) -> str:
    with open(request["path"], "r", encoding="utf-8") as f:
        return f.read()

# 4. Invoke a tool
result = gateway.call("read_file", {"path": "/etc/hosts"})
print("Output:", result.content)
print("GAA Nonce:", result.gaa.nonce)
print("Audit text:", result.to_mcp_content())
```

---

## Multi-Party Approval Quorums

For sensitive tools (e.g. database migrations, infrastructure deployments, payments), policies can require one or more signed approvals:

```python
from governed_autonomy import SignedApproval

@gateway.tool(
    description="Drop database table",
    required_fields=("table_name",),
    required_approvals=2,  # Requires 2 unique officer signatures
)
def drop_table(request: dict) -> str:
    return f"Dropped {request['table_name']}"

# Calling drop_table without approvals will raise PolicyDeniedError:
# gateway.call("drop_table", {"table_name": "users"}) -> PolicyDeniedError

# Attach valid approvals from authorized approvers:
approvals = [
    SignedApproval.issue(action="drop_table", request_digest=..., issuer=officer_1),
    SignedApproval.issue(action="drop_table", request_digest=..., issuer=officer_2),
]
result = gateway.call("drop_table", {"table_name": "users"}, approvals=approvals)
```

---

## Exposing as an MCP Server (`stdio` Transport)

If the `mcp` SDK is installed (`pip install mcp`), you can expose the gateway directly over the MCP stdio transport:

```python
from governed_autonomy.mcp_gateway import GASMCPGateway, GASMCPServer

# Initialize gateway as above
gateway = ...

# Wrap and run
server = GASMCPServer(gateway, name="governed-filesystem-tools")
server.run()
```

### Claude Desktop Configuration

Add the governed server to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "governed-tools": {
      "command": "python",
      "args": ["-m", "my_governed_tools_server"]
    }
  }
}
```

---

## Audit & Verification

At any time, operators can extract a tamper-evident audit snapshot:

```python
audit = gateway.audit_report()
print(f"Total audit frames: {audit['audit_summary']['frame_count']}")
print(f"Policy SHA-256: {audit['policy_digest']}")
```
