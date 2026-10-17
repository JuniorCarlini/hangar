-- +goose Up
CREATE TABLE projects (
    id         TEXT    PRIMARY KEY,
    slug       TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE services (
    id            TEXT    PRIMARY KEY,
    project_id    TEXT    NOT NULL REFERENCES projects (id),
    slug          TEXT    NOT NULL,
    image         TEXT    NOT NULL,
    internal_port INTEGER NOT NULL DEFAULT 0,
    memory_bytes  INTEGER NOT NULL,
    nano_cpus     INTEGER NOT NULL,
    pids_limit    INTEGER NOT NULL,
    read_only     INTEGER NOT NULL DEFAULT 0,
    command_json  TEXT    NOT NULL DEFAULT '[]',
    desired_state TEXT    NOT NULL DEFAULT 'running' CHECK (desired_state IN ('running', 'stopped')),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    UNIQUE (project_id, slug)
) STRICT;

-- Every value is encrypted (associated data = env_vars|<service_id>|<key>);
-- the secret flag only decides whether the UI shows or masks it.
CREATE TABLE env_vars (
    service_id TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value_enc  BLOB    NOT NULL,
    secret     INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (service_id, key)
) STRICT;

CREATE TABLE deployments (
    id          TEXT    PRIMARY KEY,
    service_id  TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    status      TEXT    NOT NULL CHECK (status IN ('running', 'live', 'failed', 'superseded')),
    image       TEXT    NOT NULL,
    env_hash    TEXT    NOT NULL,
    trigger     TEXT    NOT NULL,
    created_by  TEXT,
    error       TEXT,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
) STRICT;
CREATE INDEX deployments_service ON deployments (service_id, started_at DESC);

-- +goose Down
DROP TABLE deployments;
DROP TABLE env_vars;
DROP TABLE services;
DROP TABLE projects;
