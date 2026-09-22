# Google Agent-to-Agent (A2A) Protocol Integration

## Overview

In multi-agent systems, agents delegate tasks, invoke peer tools, and transfer context across trust boundaries. The **Google Agent-to-Agent (A2A) Protocol** specifies inter-agent communication and task negotiation.

The GAS A2A Integration introduces cryptographic governance to multi-agent task hand-offs:

1. **Delegation Authenticity**: The delegating agent signs an `A2ATaskDelegation` envelope containing delegator ID, recipient ID, task ID, action, arguments, and a GAA token.
2. **Deterministic Governance**: The task action is authorized against an active governance policy before the task hand-off occurs.
3. **Recipient Enforcement**: `A2AGuard` verifies that the incoming delegation is targeted to this specific agent and originates from a trusted, non-revoked peer.
4. **Replay Prevention**: The GAA nonce is claimed atomically in the recipient's replay log, preventing replay attacks or accidental duplicate task execution.

```
[ Delegator Agent ]                                      [ Recipient Agent ]
        │                                                         │
 1. Request GAA from Issuer                                       │
        │                                                         │
 2. Sign A2ATaskDelegation ─────── A2A Task Envelope ────────────►│
    (binds recipient, task, GAA)                                  │
                                                            3. A2AGuard
                                                               • Verify recipient targeting
                                                               • Verify delegator Ed25519 sig
                                                               • Claim GAA nonce atomically
                                                               • Commit execution frame to log
                                                                  │
                                                            4. Execute Task
```

---

## Code Example

### Step 1: Delegating Agent Packages Task

```python
from governed_autonomy import KeyPair, ReplayLog, TrustStore, AuthorizationIssuer, Policy
from governed_autonomy.a2a import A2ATaskDelegation

# Setup keys
issuer_key = KeyPair.generate("governor")
coordinator_key = KeyPair.generate("coordinator-agent")
worker_key_id = "worker-agent-1"

# Authorize task action
policy = ...
action_req = {"action": "sync_inventory", "warehouse_id": "wh-42", "context": {}}
gaa = issuer.authorize(action_req, policy)

# Create signed delegation
delegation = A2ATaskDelegation.create(
    delegator=coordinator_key,
    recipient_id=worker_key_id,
    task_id="task-10042",
    action="sync_inventory",
    payload={"warehouse_id": "wh-42"},
    gaa=gaa,
)

# Transmit delegation.to_dict() over A2A transport
```

### Step 2: Recipient Agent Verifies and Executes

```python
from governed_autonomy.a2a import A2AGuard, A2ATaskDelegation

# Initialize guard with worker's identity and trust store
guard = A2AGuard(
    recipient_id="worker-agent-1",
    trust_store=worker_trust_store,
    boundary=worker_execution_boundary,
)

# Receive envelope from transport
received_delegation = A2ATaskDelegation.from_dict(envelope_dict)

# Handler executed only if verification passes and nonce is claimed
def perform_sync(req: dict) -> str:
    return f"Inventory synced for {req['warehouse_id']}"

result = guard.receive_and_execute(received_delegation, perform_sync)
print("Execution result:", result)
```

---

## Failure Modes & Security Invariants

| Failure Condition | Barrier Response |
| --- | --- |
| Recipient ID does not match self | Raises `AuthorizationError("delegation recipient mismatch")` |
| Delegator public key not in trust store or revoked | Raises `AuthorizationError("unknown or revoked delegator key")` |
| Delegator signature invalid | Raises `AuthorizationError("invalid delegator signature...")` |
| Task action does not match GAA action | Raises `AuthorizationError("action mismatch...")` |
| Nonce already consumed | Raises `AuthorizationError` (duplicate nonce prevention) |
