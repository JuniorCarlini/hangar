-- +goose Up
-- Projects each person pins to the top of the sidebar, in the order they
-- were pinned. Personal: pinning changes nobody else's sidebar.
CREATE TABLE pinned_projects (
    user_id    TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    project_id TEXT    NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    pinned_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, project_id)
) STRICT;

-- +goose Down
DROP TABLE pinned_projects;
