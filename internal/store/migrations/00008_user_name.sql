-- +goose Up
-- Display name ("Olá, Junior" in the account menu); empty = derived from the
-- e-mail.
ALTER TABLE users ADD COLUMN name TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE users DROP COLUMN name;
