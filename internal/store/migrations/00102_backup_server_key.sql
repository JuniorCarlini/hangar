-- +goose Up
-- The server's own backup key, for the simple mode (no recovery kit): an
-- age identity sealed with the master key. Backups are still encrypted in
-- the bucket; the panel opens them itself to restore and download.
CREATE TABLE backup_server_key (
    id           TEXT NOT NULL PRIMARY KEY CHECK (id = 'server'),
    identity_enc BLOB NOT NULL,
    created_at   INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE backup_server_key;
