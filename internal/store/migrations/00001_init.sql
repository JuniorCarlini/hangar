-- +goose Up
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
) STRICT;

-- Hash-chained audit log: each record stores the previous record's hash, so
-- changing or removing a row breaks the chain and `hangard audit verify`
-- reports it. The triggers block UPDATE and DELETE through plain SQL; the
-- chain covers anyone who bypasses the triggers by editing the file.
CREATE TABLE audit_log (
    id           INTEGER PRIMARY KEY,
    ts           TEXT    NOT NULL,
    actor_id     TEXT,
    ip           TEXT,
    user_agent   TEXT,
    action       TEXT    NOT NULL,
    target_type  TEXT,
    target_id    TEXT,
    outcome      TEXT    NOT NULL CHECK (outcome IN ('ok', 'denied', 'error')),
    summary_json TEXT    NOT NULL DEFAULT '{}',
    prev_hash    BLOB    NOT NULL,
    hash         BLOB    NOT NULL
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is insert-only');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is insert-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_delete;
DROP TRIGGER audit_log_no_update;
DROP TABLE audit_log;
DROP TABLE settings;
