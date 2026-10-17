-- +goose Up
-- Commands saved for a service's terminal (migrate, createsuperuser…):
-- one click runs them in the container, in place of a shell. They are
-- typed by admins and run only by admins in sudo mode, with the command in
-- the audit log.
CREATE TABLE service_commands (
    id         TEXT    PRIMARY KEY,
    service_id TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    command    TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX service_commands_service ON service_commands (service_id, name);

-- +goose Down
DROP TABLE service_commands;
