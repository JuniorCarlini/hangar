-- +goose Up
-- saved_roles: the roles a restore recreated from the roles saved with the
-- dump (pg_dumpall --roles-only), as they were in the original (attributes,
-- password hash, memberships), as a JSON array. created_roles keeps the
-- ones it had to create without a password (dumps saved without roles).
ALTER TABLE backup_restores ADD COLUMN saved_roles TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE backup_restores DROP COLUMN saved_roles;
