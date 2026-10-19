-- +goose Up
-- When each person last used the panel, kept on the account. It used to be
-- read from the open sessions only, so a person whose sessions had expired
-- or who logged out showed as "never logged in". Filled from the sessions
-- still open and the login audit records.
ALTER TABLE users ADD COLUMN last_seen_at INTEGER NOT NULL DEFAULT 0;

UPDATE users SET last_seen_at = max(
    coalesce((SELECT max(s.last_seen_at) FROM sessions s WHERE s.user_id = users.id AND s.stage = 'active'), 0),
    coalesce((SELECT max(CAST(strftime('%s', substr(a.ts, 1, 19)) AS INTEGER)) FROM audit_log a
              WHERE a.actor_id = users.id AND a.action = 'auth.login.ok' AND a.outcome = 'ok'), 0)
);

-- +goose Down
ALTER TABLE users DROP COLUMN last_seen_at;
