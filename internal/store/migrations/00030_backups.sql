-- +goose Up
-- Backups (docs/09). The panel keeps only public keys: the private keys
-- live in the operator's recovery kit and never reach the server.

-- confirm_hash is the hash of the confirmation code printed in the kit;
-- typing it back proves the kit was kept (confirmed_at). Only confirmed
-- keys are encrypted to.
CREATE TABLE backup_recipients (
    id             TEXT    PRIMARY KEY,
    label          TEXT    NOT NULL,
    age_public_key TEXT    NOT NULL UNIQUE,
    confirm_hash   TEXT    NOT NULL,
    confirmed_at   INTEGER,
    created_by     TEXT,
    created_at     INTEGER NOT NULL
) STRICT;

-- S3-compatible destinations. config_enc (backup_targets|<id>|config)
-- holds endpoint, region, bucket, prefix and the write-only credential.
-- Every backup goes to every destination.
CREATE TABLE backup_targets (
    id               TEXT    PRIMARY KEY,
    name             TEXT    NOT NULL,
    provider         TEXT    NOT NULL,
    config_enc       BLOB    NOT NULL,
    lock_mode        TEXT    NOT NULL CHECK (lock_mode IN ('COMPLIANCE', 'GOVERNANCE')),
    object_lock_days INTEGER NOT NULL CHECK (object_lock_days BETWEEN 1 AND 3650),
    is_primary       INTEGER NOT NULL DEFAULT 0,
    checked_at       INTEGER,
    check_error      TEXT    NOT NULL DEFAULT '',
    created_by       TEXT,
    created_at       INTEGER NOT NULL
) STRICT;

-- What to back up and when. service_id NULL is the panel itself (one row,
-- id "bp_panel").
-- at_minute is the minute of the day (server time) of the first run;
-- every_hours repeats from there. wal turns on continuous archiving
-- (point-in-time restore); wal_since marks when, so a base backup follows.
CREATE TABLE backup_policies (
    id          TEXT    PRIMARY KEY,
    service_id  TEXT    UNIQUE REFERENCES services (id) ON DELETE CASCADE,
    enabled     INTEGER NOT NULL DEFAULT 1,
    every_hours INTEGER NOT NULL DEFAULT 24 CHECK (every_hours IN (1, 6, 12, 24)),
    at_minute   INTEGER NOT NULL DEFAULT 180 CHECK (at_minute BETWEEN 0 AND 1439),
    wal         INTEGER NOT NULL DEFAULT 0,
    wal_since   INTEGER,
    next_run_at INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
) STRICT;

-- One row per backup made (WAL segments are summed up in wal_status).
-- label keeps "project/service" after the service is gone. object_key is
-- relative to each destination's prefix; uploads_json says how each
-- destination went; check_json holds what the test restore counted.
CREATE TABLE backup_runs (
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
CREATE INDEX backup_runs_service ON backup_runs (service_id, started_at DESC);
CREATE INDEX backup_runs_started ON backup_runs (started_at DESC);

-- Continuous archiving of each PostgreSQL service: the newest WAL file in
-- the bucket and what is still waiting on the server.
CREATE TABLE wal_status (
    service_id        TEXT    PRIMARY KEY REFERENCES services (id) ON DELETE CASCADE,
    last_archived_wal TEXT    NOT NULL DEFAULT '',
    last_archived_at  INTEGER,
    pending           INTEGER NOT NULL DEFAULT 0,
    oldest_pending_at INTEGER,
    last_error        TEXT    NOT NULL DEFAULT '',
    checked_at        INTEGER NOT NULL
) STRICT;

-- Restores started from the panel. point is the minute (pitr) or the
-- backup run (dump).
CREATE TABLE backup_restores (
    id          TEXT    PRIMARY KEY,
    service_id  TEXT    REFERENCES services (id) ON DELETE SET NULL,
    label       TEXT    NOT NULL,
    mode        TEXT    NOT NULL CHECK (mode IN ('pitr', 'dump')),
    point       TEXT    NOT NULL,
    destination TEXT    NOT NULL CHECK (destination IN ('new', 'overwrite')),
    new_service TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    step        TEXT    NOT NULL DEFAULT '',
    error       TEXT,
    created_by  TEXT,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
) STRICT;
CREATE INDEX backup_restores_service ON backup_restores (service_id, started_at DESC);

-- +goose Down
DROP TABLE backup_restores;
DROP TABLE wal_status;
DROP TABLE backup_runs;
DROP TABLE backup_policies;
DROP TABLE backup_targets;
DROP TABLE backup_recipients;
