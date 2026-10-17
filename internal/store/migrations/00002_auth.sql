-- +goose Up
-- Timestamps are Unix seconds (INTEGER) so they can be compared and cleaned
-- up directly in SQL.
CREATE TABLE users (
    id              TEXT    PRIMARY KEY,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'viewer')),
    -- Encrypted with the master key; associated data = users|<id>|totp_secret_enc.
    totp_secret_enc BLOB,
    -- Last accepted 30 s step: a code is never valid twice.
    totp_last_step  INTEGER NOT NULL DEFAULT 0,
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_at       INTEGER,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
) STRICT;

CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash BLOB    NOT NULL,
    used_at   INTEGER
) STRICT;
CREATE INDEX recovery_codes_user ON recovery_codes (user_id);

-- Only the token hash is stored: whoever reads the database cannot use the session.
CREATE TABLE sessions (
    id_hash      BLOB    PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    stage        TEXT    NOT NULL CHECK (stage IN ('pending_2fa', 'active')),
    csrf_token   TEXT    NOT NULL,
    ip           TEXT,
    user_agent   TEXT,
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    sudo_until   INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX sessions_user ON sessions (user_id);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- +goose Down
DROP TABLE sessions;
DROP TABLE recovery_codes;
DROP TABLE users;
