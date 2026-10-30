-- +goose Up
-- A keyed audit chain (SEC-010). Up to here each record's hash was a plain
-- SHA-256, so whoever could write the database could rewrite the chain
-- and recompute every hash. From audit_chain.from_id on, records chain
-- with HMAC-SHA256 under a key derived from the master key, stored here
-- sealed by it (key_enc) with its SHA-256 (key_id) to tell a wrong key
-- from tampering. The first keyed record is the anchor the panel writes
-- when it keys the chain; it chains from the last plain record, so the
-- older history is pinned too. Chunks of the archive carry an HMAC of
-- their metadata (mac), checked even after their data expires.
ALTER TABLE audit_archive ADD COLUMN mac BLOB;

CREATE TABLE audit_chain (
    version    INTEGER PRIMARY KEY CHECK (version = 2),
    from_id    INTEGER NOT NULL,
    key_enc    BLOB    NOT NULL,
    key_id     BLOB    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

-- The key starts after every record that exists, so no plain record can
-- be passed off as written before it.
-- +goose StatementBegin
CREATE TRIGGER audit_chain_insert BEFORE INSERT ON audit_chain
WHEN NEW.from_id <= coalesce((SELECT max(id) FROM audit_log), 0)
  OR NEW.from_id <= coalesce((SELECT max(last_id) FROM audit_archive), 0)
BEGIN
    SELECT RAISE(ABORT, 'audit_chain must start after the existing records');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER audit_chain_no_delete BEFORE DELETE ON audit_chain
BEGIN
    SELECT RAISE(ABORT, 'audit_chain is permanent');
END;
-- +goose StatementEnd

-- Only the sealed key may change: the master key rotation re-seals it.
-- +goose StatementBegin
CREATE TRIGGER audit_chain_no_update BEFORE UPDATE ON audit_chain
WHEN NEW.version != OLD.version OR NEW.from_id != OLD.from_id
  OR NEW.key_id != OLD.key_id OR NEW.created_at != OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'audit_chain only re-seals its key');
END;
-- +goose StatementEnd

-- A chunk must hold exactly the oldest hot records, matching their hashes
-- and continuing the previous chunk; it arrives with its data, and with
-- its HMAC once the chain is keyed. A made-up chunk can no longer unlock
-- the deletion of records it does not really hold.
-- +goose StatementBegin
CREATE TRIGGER audit_archive_insert BEFORE INSERT ON audit_archive
WHEN NEW.data IS NULL OR NEW.expired_at IS NOT NULL
  OR NEW.last_id < NEW.first_id
  OR NEW.first_id IS NOT (SELECT min(id) FROM audit_log)
  OR NEW.last_id >= (SELECT max(id) FROM audit_log)
  OR NEW.records != (SELECT count(*) FROM audit_log WHERE id BETWEEN NEW.first_id AND NEW.last_id)
  OR NEW.prev_hash IS NOT (SELECT prev_hash FROM audit_log WHERE id = NEW.first_id)
  OR NEW.last_hash IS NOT (SELECT hash FROM audit_log WHERE id = NEW.last_id)
  OR NEW.prev_hash IS NOT coalesce((SELECT last_hash FROM audit_archive ORDER BY first_id DESC LIMIT 1), zeroblob(32))
  OR (NEW.mac IS NULL AND EXISTS (SELECT 1 FROM audit_chain))
BEGIN
    SELECT RAISE(ABORT, 'audit_archive chunk does not match the records it claims');
END;
-- +goose StatementEnd

-- Two changes only: dropping the data of a chunk past its retention (seven
-- years, audit.ArchiveKeep), and authenticating, once, a chunk archived
-- before the chain had a key.
DROP TRIGGER audit_archive_no_update;

-- +goose StatementBegin
CREATE TRIGGER audit_archive_no_update BEFORE UPDATE ON audit_archive
WHEN NEW.first_id != OLD.first_id OR NEW.last_id != OLD.last_id OR NEW.records != OLD.records
  OR NEW.first_ts != OLD.first_ts OR NEW.last_ts != OLD.last_ts
  OR NEW.prev_hash != OLD.prev_hash OR NEW.last_hash != OLD.last_hash
  OR NEW.data_sha256 != OLD.data_sha256 OR NEW.archived_at != OLD.archived_at
  OR NOT (
       (OLD.data IS NOT NULL AND NEW.data IS NULL AND OLD.expired_at IS NULL AND NEW.expired_at IS NOT NULL
        AND NEW.mac IS OLD.mac
        AND OLD.last_ts < strftime('%Y-%m-%dT%H:%M:%S', 'now', '-2555 days'))
    OR (OLD.mac IS NULL AND NEW.mac IS NOT NULL
        AND NEW.data IS OLD.data AND NEW.expired_at IS OLD.expired_at)
  )
BEGIN
    SELECT RAISE(ABORT, 'audit_archive only drops expired data');
END;
-- +goose StatementEnd

-- A record can be deleted only while a chunk that holds it still has its
-- data (the archiving transaction).
DROP TRIGGER audit_log_no_delete;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
WHEN NOT EXISTS (
    SELECT 1 FROM audit_archive c
    WHERE OLD.id BETWEEN c.first_id AND c.last_id AND c.data IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is insert-only');
END;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER audit_log_no_delete;

-- +goose StatementBegin
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
WHEN OLD.id > coalesce((SELECT max(last_id) FROM audit_archive), 0)
BEGIN
    SELECT RAISE(ABORT, 'audit_log is insert-only');
END;
-- +goose StatementEnd

DROP TRIGGER audit_archive_no_update;

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

DROP TRIGGER audit_archive_insert;
DROP TRIGGER audit_chain_no_update;
DROP TRIGGER audit_chain_no_delete;
DROP TRIGGER audit_chain_insert;
DROP TABLE audit_chain;
ALTER TABLE audit_archive DROP COLUMN mac;
