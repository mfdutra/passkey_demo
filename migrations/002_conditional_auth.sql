-- Make authentication challenges support conditional auth (no specific user)
-- We need to recreate the table to modify the foreign key constraint

-- Create new table without strict foreign key
CREATE TABLE IF NOT EXISTS authentication_challenges_new (
    id TEXT PRIMARY KEY,
    user_id TEXT,  -- Nullable now for conditional auth
    challenge_state BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- Copy existing data
INSERT INTO authentication_challenges_new
SELECT * FROM authentication_challenges;

-- Drop old table
DROP TABLE authentication_challenges;

-- Rename new table
ALTER TABLE authentication_challenges_new RENAME TO authentication_challenges;

-- Recreate indexes
CREATE INDEX idx_authentication_challenges_user_id ON authentication_challenges(user_id);
CREATE INDEX idx_authentication_challenges_expires_at ON authentication_challenges(expires_at);
