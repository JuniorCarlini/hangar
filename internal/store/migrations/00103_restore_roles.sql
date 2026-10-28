-- +goose Up
-- What a restore did besides the data. created_roles: the roles it had to
-- create without a password (a pg_dump does not carry roles), as a JSON
-- array, so the owner knows which ones need one. cleanup: what happened to
-- the new service of a failed restore into a new service ('removed', or
-- 'kept' when removing it failed).
ALTER TABLE backup_restores ADD COLUMN created_roles TEXT NOT NULL DEFAULT '[]';
ALTER TABLE backup_restores ADD COLUMN cleanup TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE backup_restores DROP COLUMN cleanup;
ALTER TABLE backup_restores DROP COLUMN created_roles;
