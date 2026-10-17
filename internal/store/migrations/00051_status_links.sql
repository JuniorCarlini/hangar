-- +goose Up
-- Public status links (docs/15). The token is only stored as a SHA-256 hash:
-- it is shown once, when created. service_ids_json lists the services the
-- link shows, in the order they are labelled ("Serviço A", "Serviço B"…).
CREATE TABLE status_links (
    id               TEXT    PRIMARY KEY,
    name             TEXT    NOT NULL,
    token_hash       BLOB    NOT NULL UNIQUE,
    naming           TEXT    NOT NULL CHECK (naming IN ('alias', 'generic', 'hidden')),
    service_ids_json TEXT    NOT NULL DEFAULT '[]',
    allowed_cidrs    TEXT    NOT NULL DEFAULT '', -- comma separated; '' = any address
    expires_at       INTEGER,
    revoked_at       INTEGER,
    created_by       TEXT,
    created_at       INTEGER NOT NULL,
    last_access_at   INTEGER,
    last_access_ip   TEXT    NOT NULL DEFAULT '', -- masked (189.x.x.x)
    access_count     INTEGER NOT NULL DEFAULT 0,
    access_day       INTEGER NOT NULL DEFAULT 0, -- unix day of access_today
    access_today     INTEGER NOT NULL DEFAULT 0
) STRICT;

-- The public name of a service in links using aliases ("Loja principal").
CREATE TABLE service_aliases (
    service_id   TEXT PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    public_label TEXT NOT NULL
) STRICT;

-- +goose Down
DROP TABLE service_aliases;
DROP TABLE status_links;
