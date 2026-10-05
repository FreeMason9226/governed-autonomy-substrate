CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    subject TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    email TEXT,
    display_name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (subject, tenant_id)
);

CREATE TABLE IF NOT EXISTS service_principals (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    name TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

INSERT INTO roles (id, name, description) VALUES
    ('platform_admin', 'platform_admin', 'Full platform administration'),
    ('policy_admin', 'policy_admin', 'Create and manage governance policies'),
    ('operator', 'operator', 'Submit governed operations'),
    ('auditor', 'auditor', 'Read audit evidence'),
    ('approver', 'approver', 'Approve governed policy changes'),
    ('service_principal', 'service_principal', 'Authenticated non-human principal')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS role_assignments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    role_id TEXT NOT NULL REFERENCES roles(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    assigned_by TEXT NOT NULL,
    UNIQUE (principal_id, tenant_id, role_id)
);

CREATE INDEX IF NOT EXISTS role_assignments_principal_idx
    ON role_assignments (principal_id);

CREATE TABLE IF NOT EXISTS identity_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type TEXT NOT NULL,
    principal_id TEXT NOT NULL,
    details JSONB NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS identity_events_principal_idx
    ON identity_events (principal_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS consumed_identity_tokens (
    issuer TEXT NOT NULL,
    audience TEXT NOT NULL,
    jti TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (issuer, audience, jti)
);

CREATE INDEX IF NOT EXISTS consumed_identity_tokens_expiry_idx
    ON consumed_identity_tokens (expires_at);
