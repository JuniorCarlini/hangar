-- name: GetSetting :one
SELECT value_json FROM settings WHERE key = ?;

-- name: SetSetting :exec
INSERT INTO settings (key, value_json) VALUES (?, ?)
ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json;
