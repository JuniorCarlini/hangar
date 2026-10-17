-- +goose Up
-- validate_json: command run inside the new container once it is healthy,
-- before it takes over (e.g. python manage.py check --deploy); a non-zero
-- exit keeps (or brings back) the previous version.
-- validate_timeout_s: how long it may run.
ALTER TABLE services ADD COLUMN validate_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE services ADD COLUMN validate_timeout_s INTEGER NOT NULL DEFAULT 300;

-- +goose Down
ALTER TABLE services DROP COLUMN validate_timeout_s;
ALTER TABLE services DROP COLUMN validate_json;
