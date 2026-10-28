-- +goose Up
-- consistency: how a copy of a service's volumes is kept consistent while
-- it is taken. 'pause' freezes the services that write to them for the
-- copy (seconds); 'stop' stops and starts them (the app shuts down
-- cleanly first); 'live' copies while they run (a file being written may
-- come out half done). PostgreSQL ignores it: pg_dump is consistent.
ALTER TABLE backup_policies ADD COLUMN consistency TEXT NOT NULL DEFAULT 'pause'
    CHECK (consistency IN ('pause', 'stop', 'live'));

-- +goose Down
ALTER TABLE backup_policies DROP COLUMN consistency;
