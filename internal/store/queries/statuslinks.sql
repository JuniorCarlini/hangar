-- name: CreateStatusLink :exec
INSERT INTO status_links (id, name, token_hash, naming, service_ids_json, allowed_cidrs, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListStatusLinks :many
SELECT * FROM status_links WHERE revoked_at IS NULL ORDER BY created_at DESC;

-- name: GetStatusLinkByHash :one
SELECT * FROM status_links WHERE token_hash = ?;

-- name: RevokeStatusLink :execrows
UPDATE status_links SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: RevokeAllStatusLinks :execrows
UPDATE status_links SET revoked_at = ? WHERE revoked_at IS NULL;

-- name: RecordStatusLinkAccess :exec
UPDATE status_links
SET access_count = access_count + 1,
    access_today = CASE WHEN access_day = sqlc.arg(day) THEN access_today + 1 ELSE 1 END,
    access_day = sqlc.arg(day),
    last_access_at = sqlc.arg(now),
    last_access_ip = sqlc.arg(ip)
WHERE id = sqlc.arg(id);

-- name: ListServiceAliases :many
SELECT * FROM service_aliases;

-- name: SetServiceAlias :exec
INSERT INTO service_aliases (service_id, public_label) VALUES (?, ?)
ON CONFLICT (service_id) DO UPDATE SET public_label = excluded.public_label;

-- name: DeleteServiceAlias :exec
DELETE FROM service_aliases WHERE service_id = ?;
