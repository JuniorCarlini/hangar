-- +goose Up
-- The team: who can reach which projects, and invitations.
--
-- all_projects = 1 lets a user see every project (owners and admins always
-- do). With 0, user_projects lists the only projects the user sees; every
-- other project, and the server-wide pages, are out of reach.
ALTER TABLE users ADD COLUMN all_projects INTEGER NOT NULL DEFAULT 1;

CREATE TABLE user_projects (
    user_id    TEXT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, project_id)
) STRICT;

-- An invitation is a one-time link (only its hash is stored) that lets the
-- invited person set a password and join with the role and projects chosen
-- by the owner. It expires; once used it cannot be used again.
CREATE TABLE invites (
    id            TEXT    PRIMARY KEY,
    token_hash    TEXT    NOT NULL UNIQUE,
    email         TEXT    NOT NULL COLLATE NOCASE,
    role          TEXT    NOT NULL CHECK (role IN ('admin', 'operator', 'viewer')),
    all_projects  INTEGER NOT NULL DEFAULT 1,
    projects_json TEXT    NOT NULL DEFAULT '[]',
    created_by    TEXT,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    used_at       INTEGER
) STRICT;

-- +goose Down
DROP TABLE invites;
DROP TABLE user_projects;
ALTER TABLE users DROP COLUMN all_projects;
