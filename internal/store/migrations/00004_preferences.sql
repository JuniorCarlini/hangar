-- +goose Up
-- Per-user UI preferences (docs/22). NULL locale = follow the browser.
ALTER TABLE users ADD COLUMN locale TEXT;
ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'system' CHECK (theme IN ('system', 'dark', 'light'));

-- +goose Down
ALTER TABLE users DROP COLUMN theme;
ALTER TABLE users DROP COLUMN locale;
