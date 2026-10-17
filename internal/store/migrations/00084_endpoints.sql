-- +goose Up
-- HTTP endpoints a service exposes (docs/28): a container port with a label
-- and whether it is public (gets an external link) or internal only. A
-- service can have several (e.g. RustFS: console + S3/CDN). Additive: a
-- service with no endpoint rows keeps routing its domains to internal_port.
CREATE TABLE endpoints (
    id            TEXT    PRIMARY KEY,
    service_id    TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    name          TEXT    NOT NULL DEFAULT '',
    port          INTEGER NOT NULL,
    label         TEXT    NOT NULL DEFAULT '',
    public        INTEGER NOT NULL DEFAULT 0,
    sslip_enabled INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    UNIQUE (service_id, port)
) STRICT;
CREATE INDEX endpoints_service ON endpoints (service_id);

-- A domain may point at a specific endpoint (its port); NULL keeps the old
-- behaviour of routing to the service's internal_port.
ALTER TABLE domains ADD COLUMN endpoint_id TEXT REFERENCES endpoints (id) ON DELETE CASCADE;

-- +goose Down
-- SQLite refuses DROP COLUMN on a column with a foreign key: rebuild domains
-- as it was before (00005).
CREATE TABLE domains_old (
    id         TEXT    PRIMARY KEY,
    service_id TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    hostname   TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;
INSERT INTO domains_old (id, service_id, hostname, created_at)
SELECT id, service_id, hostname, created_at FROM domains;
DROP TABLE domains;
ALTER TABLE domains_old RENAME TO domains;
CREATE INDEX domains_service ON domains (service_id);
DROP TABLE endpoints;
