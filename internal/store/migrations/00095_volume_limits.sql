-- +goose Up
-- Volumes with a size limit (docs/05, internal/volumes): the volume's files
-- live in a disk image of size_bytes, which a root unit creates and mounts.
-- One row per Docker volume (hangar_<project>_<service>_<name>), on the
-- service that owns it. No reference to services: a deleted service's row
-- stays (state 'remove') until the root unit has deleted the image.
--
-- state: 'new' (the volume did not exist: wait for the image, then deploy),
-- 'active', 'migrate' (move existing data into the image), 'unlimit' (move
-- it back to a plain volume), 'remove' (delete the image), 'failed' (a
-- limit that could not be applied; error says why, the image is cleaned up).
-- step is where a migrate or unlimit is; restart_json the services it
-- stopped and starts again at the end.
CREATE TABLE volume_limits (
    volume       TEXT    PRIMARY KEY,
    project_id   TEXT    NOT NULL,
    service_id   TEXT    NOT NULL,
    name         TEXT    NOT NULL,
    size_bytes   INTEGER NOT NULL CHECK (size_bytes > 0),
    state        TEXT    NOT NULL CHECK (state IN ('new', 'active', 'migrate', 'unlimit', 'remove', 'failed')),
    step         TEXT    NOT NULL DEFAULT '',
    error        TEXT    NOT NULL DEFAULT '',
    restart_json TEXT    NOT NULL DEFAULT '[]',
    created_by   TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

CREATE INDEX volume_limits_service ON volume_limits (service_id);

-- +goose Down
DROP TABLE volume_limits;
