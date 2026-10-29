-- +goose Up
-- Audit retention without breaking the chain (docs/20): records older than
-- the hot window move, a calendar month at a time, into one compressed
-- chunk here, in the same transaction that deletes them. Each chunk keeps
-- the hash its first record chained from and the hash of its last one, so
-- the chain still verifies from genesis to the newest record. When a
-- chunk's own retention ends only its data goes (data = NULL): the hashes,
-- ids and the SHA-256 of the data stay, a few hundred bytes a month.
CREATE TABLE audit_archive (
    first_id    INTEGER PRIMARY KEY,
    last_id     INTEGER NOT NULL,
    records     INTEGER NOT NULL,
    first_ts    TEXT    NOT NULL,
    last_ts     TEXT    NOT NULL,
    prev_hash   BLOB    NOT NULL,
    last_hash   BLOB    NOT NULL,
    data        BLOB,             -- gzip of one JSON record per line; NULL once expired
    data_sha256 BLOB    NOT NULL,
    archived_at INTEGER NOT NULL,
    expired_at  INTEGER
) STRICT;

-- +goose StatementBegin
CREATE TRIGGER audit_archive_no_delete BEFORE DELETE ON audit_archive
BEGIN
    SELECT RAISE(ABORT, 'audit_archive is insert-only');
END;
-- +goose StatementEnd

-- The only change a chunk accepts is dropping its data once.
-- +goose StatementBegin
CREATE TRIGGER audit_archive_no_update BEFORE UPDATE ON audit_archive
WHEN OLD.data IS NULL OR NEW.data IS NOT NULL OR NEW.expired_at IS NULL
  OR NEW.first_id != OLD.first_id OR NEW.last_id != OLD.last_id OR NEW.records != OLD.records
  OR NEW.first_ts != OLD.first_ts OR NEW.last_ts != OLD.last_ts
  OR NEW.prev_hash != OLD.prev_hash OR NEW.last_hash != OLD.last_hash
  OR NEW.data_sha256 != OLD.data_sha256 OR NEW.archived_at != OLD.archived_at
BEGIN
    SELECT RAISE(ABORT, 'audit_archive only drops expired data');
END;
-- +goose StatementEnd

-- Records can be deleted only once a chunk holds them.
DROP TRIGGER audit_log_no_delete;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
WHEN OLD.id > coalesce((SELECT max(last_id) FROM audit_archive), 0)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is insert-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_delete;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is insert-only');
END;
-- +goose StatementEnd

DROP TRIGGER audit_archive_no_update;
DROP TRIGGER audit_archive_no_delete;
DROP TABLE audit_archive;
