-- +goose Up
-- A project restored from a project backup (docs/09 "Backup do projeto"):
-- always a new project, filled in the background. The row shows on the new
-- project's pages while it runs and, once done, what was left for the
-- owner to decide (domains left off, connections that are not on this
-- server, roles created without a password, services that did not start).
CREATE TABLE project_restores (
    id          TEXT    PRIMARY KEY,
    project_id  TEXT    NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    source      TEXT    NOT NULL,
    file_name   TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    step        TEXT    NOT NULL DEFAULT '',
    error       TEXT,
    notes_json  TEXT    NOT NULL DEFAULT '{}',
    created_by  TEXT,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
) STRICT;
CREATE INDEX project_restores_project ON project_restores (project_id, started_at DESC);

-- +goose Down
DROP TABLE project_restores;
