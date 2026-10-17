-- +goose Up
-- maintenance: while 1 the edge answers every host of the service with the
-- "maintenance" page instead of proxying to it; the container keeps running.
ALTER TABLE services ADD COLUMN maintenance INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE services DROP COLUMN maintenance;
