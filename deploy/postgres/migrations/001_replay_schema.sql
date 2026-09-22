CREATE TABLE IF NOT EXISTS consumed_nonces (
    nonce TEXT PRIMARY KEY,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS replay_frames (
    sequence BIGSERIAL PRIMARY KEY,
    frame_id TEXT UNIQUE NOT NULL,
    nonce TEXT,
    frame_json JSONB NOT NULL,
    frame_hash TEXT NOT NULL,
    previous_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS replay_frames_nonce_idx ON replay_frames (nonce);
