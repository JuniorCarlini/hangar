-- +goose Up
-- The account lock after repeated failed logins becomes temporary. A
-- permanent lock let anyone who knew the owner's e-mail lock the only owner
-- out for good, and only SSH (hangard user unlock) could open it again.
--   locked_until: Unix seconds; the account is locked while it is in the
--                 future. NULL or past means unlocked.
--   lock_count:   locks in a row, so each new lock lasts twice as long
--                 (15 min, 30 min, ... up to 24 h). A successful login or
--                 an unlock clears it.
--   failed_since: start of the window failed_logins counts in; failures
--                 older than the window are forgotten.
ALTER TABLE users ADD COLUMN locked_until INTEGER;
ALTER TABLE users ADD COLUMN lock_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN failed_since INTEGER;
-- Accounts already locked get the shortest lock counted from when they were
-- locked: in practice, they open again.
UPDATE users SET locked_until = locked_at + 900, lock_count = 1, failed_logins = 0
WHERE locked_at IS NOT NULL;
ALTER TABLE users DROP COLUMN locked_at;

-- +goose Down
ALTER TABLE users ADD COLUMN locked_at INTEGER;
-- Only locks still running come back (as permanent ones, the old meaning).
UPDATE users SET locked_at = unixepoch() WHERE locked_until > unixepoch();
ALTER TABLE users DROP COLUMN failed_since;
ALTER TABLE users DROP COLUMN lock_count;
ALTER TABLE users DROP COLUMN locked_until;
