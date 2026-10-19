-- +goose Up
-- A disk mounted read-only in the container (name:/path:ro or read_only:
-- true in templates and compose imports): the app reads the files, and a
-- bug or an intrusion in it cannot change them.
ALTER TABLE service_volumes ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE service_volumes DROP COLUMN read_only;
