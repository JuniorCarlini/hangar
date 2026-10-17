-- +goose Up
-- Build from Git (docs/07, Etapa 10). A service with a row here is built
-- from its repository on every deploy; services.image then holds the local
-- image repository (hangar/<project>/<service>).
--
-- token_enc: read-only clone token (service_git|<id>|token).
-- webhook_token_hash: SHA-256 of the random token in /hooks/git/<token>,
-- used to find the service; the token itself and the HMAC secret are kept
-- encrypted (service_git|<id>|webhook_token, |webhook_secret) so an admin in
-- sudo mode can show them again to paste into GitHub.
CREATE TABLE service_git (
    service_id         TEXT    PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    repo_url           TEXT    NOT NULL,
    branch             TEXT    NOT NULL,
    subdir             TEXT    NOT NULL DEFAULT '',
    dockerfile         TEXT    NOT NULL DEFAULT 'Dockerfile',
    token_enc          BLOB,
    webhook_token_hash TEXT    UNIQUE,
    webhook_token_enc  BLOB,
    webhook_secret_enc BLOB,
    updated_at         INTEGER NOT NULL
) STRICT;

-- Anti-replay: a GitHub delivery id is accepted once.
CREATE TABLE webhook_deliveries (
    delivery_id TEXT    PRIMARY KEY,
    service_id  TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    received_at INTEGER NOT NULL
) STRICT;
CREATE INDEX webhook_deliveries_received ON webhook_deliveries (received_at);

-- What a build deployed: the commit and the first line of its message.
ALTER TABLE deployments ADD COLUMN commit_sha TEXT NOT NULL DEFAULT '';
ALTER TABLE deployments ADD COLUMN commit_message TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE deployments DROP COLUMN commit_message;
ALTER TABLE deployments DROP COLUMN commit_sha;
DROP TABLE webhook_deliveries;
DROP TABLE service_git;
