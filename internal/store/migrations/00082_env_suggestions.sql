-- +goose Up
-- Variables a Git service's repository suggests (its .env.example), read
-- at each build. vars_json: [{"k":..., "v":...}], with the example value
-- left empty when it looks like a secret. digest: hash of the keys;
-- dismissed_digest: the digest the operator dismissed, so the card stays
-- hidden until the file gains or loses a key.
CREATE TABLE service_env_suggestions (
    service_id       TEXT    PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    file             TEXT    NOT NULL,
    vars_json        TEXT    NOT NULL,
    digest           TEXT    NOT NULL,
    dismissed_digest TEXT    NOT NULL DEFAULT '',
    updated_at       INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE service_env_suggestions;
