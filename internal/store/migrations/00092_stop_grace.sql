-- +goose Up
-- How long a stop waits after SIGTERM before killing the container, in
-- seconds (docs/08: stop_grace_period in templates and compose imports). 0
-- keeps the default (30 s); the panel caps it at 120 s. A game or database
-- server that saves its state on shutdown needs more than the default.
ALTER TABLE services ADD COLUMN stop_grace_s INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE services DROP COLUMN stop_grace_s;
