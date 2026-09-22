"""
GAS Ecosystem Demo: Model Context Protocol (MCP) Tool Execution.

Demonstrates:
- Creating a governed MCP gateway.
- Registering tools with required parameters and validation.
- Invoking tools through the GAS execution barrier.
- Inspecting the issued GAA token and append-only audit trail.
"""

from governed_autonomy import (
    GASMCPGateway,
    KeyPair,
    MCPGatewayContext,
    ReplayLog,
    TrustStore,
)


def main() -> None:
    print("=== GAS MCP Gateway Demo ===")

    # 1. Provision security credentials
    issuer_key = KeyPair.generate("mcp-gateway-issuer")
    trust = TrustStore()
    trust.add(issuer_key.key_id, issuer_key.public_key)
    replay = ReplayLog()

    # 2. Initialize gateway
    gateway = GASMCPGateway.create(
        issuer_key=issuer_key,
        trust_store=trust,
        replay_log=replay,
    )

    # 3. Register governed tools using decorator
    @gateway.tool(
        description="Query inventory count for a product SKU",
        required_fields=("sku", "warehouse_id"),
    )
    def check_inventory(request: dict) -> dict:
        sku = request["sku"]
        warehouse = request["warehouse_id"]
        # Simulated database lookup
        return {"sku": sku, "warehouse": warehouse, "in_stock": 142}

    print(f"Registered tool: {gateway.list_tools()[0].name}")

    # 4. Invoke tool under governance with caller context
    context = MCPGatewayContext(agent_id="claude-agent-1", tenant_id="retail-corp")
    result = gateway.call(
        "check_inventory",
        {"sku": "SKU-9921", "warehouse_id": "WH-US-EAST"},
        context=context,
    )

    print("\n--- Execution Succeeded ---")
    print(f"Tool Output:      {result.content}")
    print(f"GAA Nonce:        {result.gaa.nonce}")
    print(f"GAA Policy ID:    {result.gaa.decision['policy']}")
    print(f"GAA Expires At:   {result.gaa.expires_at}")

    # 5. Inspect MCP-formatted content
    mcp_items = result.to_mcp_content()
    print("\n--- MCP Response Content ---")
    for item in mcp_items:
        print(f"[{item['type']}] {item['text']}")

    # 6. Audit summary
    summary = replay.audit_summary()
    print(f"\nAudit Log Frames: {summary['frame_count']} (Chain Verified: {replay.verify_chain()})")


if __name__ == "__main__":
    main()
