# Policy schema and registry

Policies are JSON documents validated against a strict JSON Schema (draft 2020-12),
`schemas/policy.schema.json` (the packaged copy lives in
`src/governed_autonomy/schemas/policy.schema.json`; the root path is a symlink to it).
All objects use `additionalProperties: false`.

## Fields

| Field | Required | Description |
| --- | --- | --- |
| `id` | yes | Lowercase identifier (`[a-z0-9][a-z0-9._-]*`). |
| `name` | yes | Human-readable name. |
| `version` | yes | Semantic version (SemVer 2.0.0), e.g. `1.2.0` or `2.0.0-rc.1`. |
| `description` | yes | What the policy is for. |
| `rate_limits` | no | List of `{action, max_requests, window_seconds, scope?}`; scope is `agent`, `tenant` or `global`. |
| `allowed_actions` | no | `{allow?: [...], deny?: [...]}`; at least one list is required. |
| `escalation_rules` | no | List of `{id, condition, escalate_to, require_approvals?, timeout_seconds?, description?}`. `condition` supports `actions`, `min_risk_score` (0-1) and `min_amount`. |

Examples are in `examples/policies/` (`rate-limit.json`, `allowed-actions.json`,
`escalation.json`, `combined.json`).

## Versioning rules

* `(id, version)` is immutable. Registering the same pair with identical content is
  idempotent; different content raises `PolicyImmutabilityError`. Publish changes as a new version.
* Each version stores a SHA-256 content hash of the canonical JSON (sorted keys, compact separators).
* Ordering follows SemVer precedence: pre-releases sort before the release, build metadata is ignored.

## Registry usage

```python
from governed_autonomy.policy_registry import FilePolicyStorage, VersionedPolicyRegistry

registry = VersionedPolicyRegistry()                      # in-memory
registry = VersionedPolicyRegistry(FilePolicyStorage("policies"))  # file-based, write-once files

stored = registry.register(policy_dict)          # validates; returns StoredPolicy
registry.get("combined-basic", "1.2.0")
registry.latest("combined-basic")
registry.list_versions("combined-basic")         # ascending SemVer order
```

Invalid policies raise `PolicyValidationError`; unknown ids/versions raise `PolicyNotFoundError`.
Custom backends implement the `PolicyStorage` protocol (`get`, `put`, `versions`).
