-- +goose Up
-- Git credentials kept in one place (a token typed once, used by many
-- services). project_id NULL = any project on the server; otherwise only
-- that project's services can use it. Replacing the token here changes it
-- for every service that uses the credential at their next deploy.
--
-- token_enc: AD "git_credentials|<id>|token". token_hint: the last four
-- characters, to tell two tokens apart (the token is never shown again).
CREATE TABLE git_credentials (
    id           TEXT    PRIMARY KEY,
    project_id   TEXT    REFERENCES projects (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    host         TEXT    NOT NULL,
    token_enc    BLOB    NOT NULL,
    token_hint   TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    last_used_at INTEGER
) STRICT;
CREATE INDEX git_credentials_project ON git_credentials (project_id);

-- A service uses a saved credential (credential_id) or, as before, a token
-- of its own (token_enc); never both. Deleting a credential in use is
-- refused by the panel; SET NULL is the safety net.
ALTER TABLE service_git ADD COLUMN credential_id TEXT REFERENCES git_credentials (id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE service_git DROP COLUMN credential_id;
DROP TABLE git_credentials;
