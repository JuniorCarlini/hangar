-- +goose Up
-- Automatic deploys by polling: with auto_deploy on, the panel reads the
-- branch's head every minute and deploys each new commit. auto_seen is the
-- last head it saw ("" until the first look, which only notes it), so a
-- restart never redeploys what was already there.
ALTER TABLE service_git ADD COLUMN auto_deploy INTEGER NOT NULL DEFAULT 0;
ALTER TABLE service_git ADD COLUMN auto_seen TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE service_git DROP COLUMN auto_seen;
ALTER TABLE service_git DROP COLUMN auto_deploy;
