-- +goose Up
-- Deploy pipeline (docs/07): each deploy records its phase, a short log and
-- the exact image that went live (digest or ID), which rollback reuses.
ALTER TABLE deployments ADD COLUMN phase TEXT NOT NULL DEFAULT '';
ALTER TABLE deployments ADD COLUMN log TEXT NOT NULL DEFAULT '';
ALTER TABLE deployments ADD COLUMN image_ref TEXT NOT NULL DEFAULT '';
-- predeploy_json: command run once before switching (e.g. migrate);
-- health_path: HTTP path that says the new version is ready.
ALTER TABLE services ADD COLUMN predeploy_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE services ADD COLUMN health_path TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE services DROP COLUMN health_path;
ALTER TABLE services DROP COLUMN predeploy_json;
ALTER TABLE deployments DROP COLUMN image_ref;
ALTER TABLE deployments DROP COLUMN log;
ALTER TABLE deployments DROP COLUMN phase;
