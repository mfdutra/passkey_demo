-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_users_username ON users(username);

-- Passkey credentials table
CREATE TABLE IF NOT EXISTS passkey_credentials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    backup_eligible INTEGER NOT NULL DEFAULT 0,
    backup_state INTEGER NOT NULL DEFAULT 0,
    attestation_format TEXT,
    attestation_data BLOB,
    created_at TEXT NOT NULL,
    last_used_at TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_passkey_credentials_user_id ON passkey_credentials(user_id);

-- Registration challenges (temporary storage)
CREATE TABLE IF NOT EXISTS registration_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    challenge_state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_registration_challenges_user_id ON registration_challenges(user_id);
CREATE INDEX idx_registration_challenges_expires_at ON registration_challenges(expires_at);

-- Authentication challenges (temporary storage)
CREATE TABLE IF NOT EXISTS authentication_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    challenge_state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_authentication_challenges_user_id ON authentication_challenges(user_id);
CREATE INDEX idx_authentication_challenges_expires_at ON authentication_challenges(expires_at);

-- Sessions table (managed by tower-sessions)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    expiry_date INTEGER NOT NULL
);

CREATE INDEX idx_sessions_expiry_date ON sessions(expiry_date);
