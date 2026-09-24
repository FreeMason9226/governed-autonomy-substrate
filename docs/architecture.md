# Enforced Separation Architecture

```mermaid
flowchart LR
    A[Execution nodes\nno private keys] -->|signed identity token| G[Governance service]
    G --> K[KMS / HSM\nprivate signing key]
    G --> R[(Replay buffer\nwrite ACL)]
    G --> L[Integrity ledger\nCID compact record]
    G --> P[Immutable policy registry\nadmin quorum]
    G --> E[Signed GAA]
    E --> A
    A -->|valid GAA only| X[Execution boundary]
    X -->|execution evidence capability| G
```

Execution images contain no issuer private key. Network policy permits governance calls
only through the governance service endpoint; replay persistence and KMS access are not
exposed to execution pods.