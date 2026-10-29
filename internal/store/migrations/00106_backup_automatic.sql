-- +goose Up
-- Every stateful service is backed up whole, the way Hangar picks
-- (docs/09): a template's own recipe (a new kind of run, 'recipe'),
-- pg_dump, or a copy of the volumes with a database stopped and anything
-- else paused.
--
-- backup_runs.kind gains 'recipe': SQLite cannot change a CHECK in place,
-- so the table is rebuilt with the same columns and rows (nothing
-- references it).
CREATE TABLE backup_runs_new (
    id           TEXT    PRIMARY KEY,
    service_id   TEXT    REFERENCES services (id) ON DELETE SET NULL,
    label        TEXT    NOT NULL,
    kind         TEXT    NOT NULL CHECK (kind IN ('pg_dump', 'pg_base', 'redis', 'volume', 'recipe', 'panel', 'bucket_sync')),
    trigger      TEXT    NOT NULL,
    class        TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    object_key   TEXT    NOT NULL DEFAULT '',
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    sha256       TEXT    NOT NULL DEFAULT '',
    verified     INTEGER NOT NULL DEFAULT 0,
    check_json   TEXT    NOT NULL DEFAULT '{}',
    uploads_json TEXT    NOT NULL DEFAULT '[]',
    warning      TEXT    NOT NULL DEFAULT '',
    error        TEXT,
    created_by   TEXT,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER
) STRICT;
INSERT INTO backup_runs_new SELECT id, service_id, label, kind, trigger, class, status, object_key, size_bytes, sha256,
    verified, check_json, uploads_json, warning, error, created_by, started_at, finished_at FROM backup_runs;
DROP TABLE backup_runs;
ALTER TABLE backup_runs_new RENAME TO backup_runs;
CREATE INDEX backup_runs_service ON backup_runs (service_id, started_at DESC);
CREATE INDEX backup_runs_started ON backup_runs (started_at DESC);

-- How a copy is taken is no longer a choice: backup_policies.consistency
-- stays (dropping a column with a CHECK means rebuilding that table too)
-- but is no longer read; every row goes back to the default so nothing
-- suggests a choice is still kept.
UPDATE backup_policies SET consistency = 'pause' WHERE consistency <> 'pause';

-- +goose Down
DELETE FROM backup_runs WHERE kind = 'recipe';
CREATE TABLE backup_runs_old (
    id           TEXT    PRIMARY KEY,
    service_id   TEXT    REFERENCES services (id) ON DELETE SET NULL,
    label        TEXT    NOT NULL,
    kind         TEXT    NOT NULL CHECK (kind IN ('pg_dump', 'pg_base', 'redis', 'volume', 'panel', 'bucket_sync')),
    trigger      TEXT    NOT NULL,
    class        TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    object_key   TEXT    NOT NULL DEFAULT '',
    size_bytes   INTEGER NOT NULL DEFAULT 0,
    sha256       TEXT    NOT NULL DEFAULT '',
    verified     INTEGER NOT NULL DEFAULT 0,
    check_json   TEXT    NOT NULL DEFAULT '{}',
    uploads_json TEXT    NOT NULL DEFAULT '[]',
    warning      TEXT    NOT NULL DEFAULT '',
    error        TEXT,
    created_by   TEXT,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER
) STRICT;
INSERT INTO backup_runs_old SELECT id, service_id, label, kind, trigger, class, status, object_key, size_bytes, sha256,
    verified, check_json, uploads_json, warning, error, created_by, started_at, finished_at FROM backup_runs;
DROP TABLE backup_runs;
ALTER TABLE backup_runs_old RENAME TO backup_runs;
CREATE INDEX backup_runs_service ON backup_runs (service_id, started_at DESC);
CREATE INDEX backup_runs_started ON backup_runs (started_at DESC);
