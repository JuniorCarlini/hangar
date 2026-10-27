-- +goose Up
-- Disks removed from a service whose data still has to go. The container
-- keeps the volume mounted until the next deploy replaces it, so the data
-- is deleted after a deploy goes live without the disk. Adding a disk with
-- the same name before that takes it out of here: its data comes back.
CREATE TABLE volume_trash (
    service_id TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (service_id, name)
) STRICT;

-- +goose Down
DROP TABLE volume_trash;
