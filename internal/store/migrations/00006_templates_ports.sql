-- +goose Up
-- Services created from a template keep its id; stateful services (databases)
-- are never run twice at once. health_json and cap_add_json hold the
-- healthcheck and extra capabilities ('' = none / the default set).
ALTER TABLE services ADD COLUMN template TEXT NOT NULL DEFAULT '';
ALTER TABLE services ADD COLUMN stateful INTEGER NOT NULL DEFAULT 0;
ALTER TABLE services ADD COLUMN health_json TEXT NOT NULL DEFAULT '';
ALTER TABLE services ADD COLUMN cap_add_json TEXT NOT NULL DEFAULT '';

-- Named volumes (docs/05): hangar_<project>_<service>_<name>.
CREATE TABLE service_volumes (
    service_id TEXT NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    PRIMARY KEY (service_id, name)
) STRICT;

-- What other services may reference as ${{service.KEY}} (e.g. DATABASE_URL).
-- Encrypted like variables (service_exports|<service_id>|<key>).
CREATE TABLE service_exports (
    service_id TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value_enc  BLOB    NOT NULL,
    secret     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (service_id, key)
) STRICT;

-- Ports published on the host (the "Ports" tab).
CREATE TABLE ports (
    id             TEXT    PRIMARY KEY,
    service_id     TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    host_port      INTEGER NOT NULL,
    container_port INTEGER NOT NULL,
    protocol       TEXT    NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    access         TEXT    NOT NULL CHECK (access IN ('any', 'ips', 'localhost')),
    allowed_ips    TEXT    NOT NULL DEFAULT '[]',
    expires_at     INTEGER,
    created_by     TEXT,
    created_at     INTEGER NOT NULL,
    UNIQUE (host_port, protocol)
) STRICT;
CREATE INDEX ports_service ON ports (service_id);

-- Connected projects see each other's services by container name.
CREATE TABLE project_links (
    project_a  TEXT    NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    project_b  TEXT    NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (project_a, project_b),
    CHECK (project_a < project_b)
) STRICT;

-- +goose Down
DROP TABLE project_links;
DROP TABLE ports;
DROP TABLE service_exports;
DROP TABLE service_volumes;
ALTER TABLE services DROP COLUMN cap_add_json;
ALTER TABLE services DROP COLUMN health_json;
ALTER TABLE services DROP COLUMN stateful;
ALTER TABLE services DROP COLUMN template;
