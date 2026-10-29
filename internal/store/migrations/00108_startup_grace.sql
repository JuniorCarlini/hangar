-- +goose Up
-- startup_grace_s: how long a new version may take to start answering its
-- health check before the deploy gives up (an app that migrates or uploads
-- its static files before it listens). 0 = the panel's default, so raising
-- the default later reaches every service that never chose a value.
ALTER TABLE services ADD COLUMN startup_grace_s INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE services DROP COLUMN startup_grace_s;
