-- +goose Up
-- Marks a user drops in a service's log ("marcar"): the container log
-- itself cannot be written, so the mark lives here and the log view places
-- it at its moment, for anyone who opens the log later.
CREATE TABLE log_marks (
    id         TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    at         INTEGER NOT NULL, -- unix nanoseconds
    user_id    TEXT NOT NULL,
    user_name  TEXT NOT NULL
);
CREATE INDEX log_marks_service_at ON log_marks (service_id, at);

-- +goose Down
DROP TABLE log_marks;
