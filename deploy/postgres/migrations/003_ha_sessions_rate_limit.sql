CREATE TABLE IF NOT EXISTS gas_oidc_sessions (
    token_hash TEXT PRIMARY KEY,
    record_type TEXT NOT NULL CHECK (record_type IN ('pending', 'session')),
    payload JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS gas_oidc_sessions_expiry_idx
    ON gas_oidc_sessions (expires_at);

CREATE TABLE IF NOT EXISTS gas_rate_limit_hits (
    namespace TEXT NOT NULL,
    client_key TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS gas_rate_limit_window_idx
    ON gas_rate_limit_hits (namespace, client_key, observed_at);
