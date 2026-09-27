CREATE TABLE IF NOT EXISTS gas_tenants (
    tenant_id TEXT PRIMARY KEY,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gas_service_principals (
    principal_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    roles JSONB NOT NULL,
    allowed_actions JSONB NOT NULL,
    allowed_environments JSONB NOT NULL,
    allowed_sources JSONB NOT NULL,
    scope JSONB NOT NULL,
    public_key TEXT,
    key_status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gas_policies (
    policy_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    policy_json JSONB NOT NULL,
    published BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (policy_id, version)
);

CREATE TABLE IF NOT EXISTS gas_authorizations (
    authorization_id TEXT PRIMARY KEY,
    policy_id TEXT NOT NULL,
    request_json JSONB NOT NULL,
    context_json JSONB NOT NULL,
    mesh_inputs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    artifact_json JSONB,
    result_json JSONB,
    error_text TEXT,
    idempotency_key TEXT UNIQUE,
    request_digest TEXT NOT NULL,
    ttl_seconds INTEGER NOT NULL DEFAULT 300,
    approvals_count INTEGER NOT NULL DEFAULT 0,
    required_approvals INTEGER NOT NULL DEFAULT 0,
    execution_attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    next_attempt_at DOUBLE PRECISION,
    expires_at BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gas_approval_decisions (
    approval_id BIGSERIAL PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES gas_authorizations(authorization_id) ON DELETE CASCADE,
    decision TEXT NOT NULL,
    actor_id TEXT,
    rationale TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS gas_mesh_sources (
    source_id TEXT PRIMARY KEY,
    source_json JSONB NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
