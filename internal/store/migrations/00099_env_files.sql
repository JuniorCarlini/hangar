-- +goose Up
-- The .env file of a service as its operator wrote it: comments, section
-- titles, blank lines and order. The variables themselves stay in env_vars
-- (what the container receives); this is how the editor shows them back.
-- Encrypted like the values it holds.
CREATE TABLE service_env_files (
    service_id TEXT    PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    text_enc   BLOB    NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE service_env_files;
