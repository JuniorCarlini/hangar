-- +goose Up
-- The edge's DNS settings, set from the panel (no SSH): the base domain whose
-- wildcard certificate is obtained by DNS-01, the DNS provider and its API
-- token. The token is encrypted with the master key (associated data
-- edge_settings|1|dns_token). One row; an empty base_domain means "use what
-- hangar.toml says", which stays as the install-time bootstrap.
CREATE TABLE edge_settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    base_domain   TEXT    NOT NULL DEFAULT '',
    dns_provider  TEXT    NOT NULL DEFAULT '',
    dns_token_enc BLOB,
    updated_by    TEXT,
    updated_at    INTEGER NOT NULL
);

-- +goose Down
DROP TABLE edge_settings;
