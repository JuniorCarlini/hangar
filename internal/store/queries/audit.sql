-- name: LastAuditHash :one
SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1;

-- name: InsertAudit :one
INSERT INTO audit_log (
    ts, actor_id, ip, user_agent, action, target_type, target_id, outcome, summary_json, prev_hash, hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: ListAuditAfter :many
SELECT id, ts, actor_id, ip, user_agent, action, target_type, target_id, outcome, summary_json, prev_hash, hash
FROM audit_log
WHERE id > ?
ORDER BY id
LIMIT ?;

-- name: RecentActivity :many
-- The latest audit records of the given actions, with who did it and which
-- service they touched (when it still exists), for the overview feed.
SELECT a.id, a.ts, a.action, a.outcome, a.summary_json,
       COALESCE(u.name, '') AS user_name, COALESCE(u.email, '') AS user_email,
       COALESCE(p.slug, '') AS project_slug, COALESCE(s.slug, '') AS service_slug
FROM audit_log a
LEFT JOIN users u ON u.id = a.actor_id
LEFT JOIN services s ON a.target_type = 'service' AND s.id = a.target_id
LEFT JOIN projects p ON p.id = s.project_id
WHERE a.action IN (sqlc.slice(actions))
ORDER BY a.id DESC
LIMIT ?;

-- name: OldestAudit :one
SELECT id, ts FROM audit_log ORDER BY id LIMIT 1;

-- name: LastAuditBefore :one
-- The newest record older than ts, never the newest of all: the hot table
-- always keeps one record, so new ids keep growing past the archived ones
-- (INTEGER PRIMARY KEY reuses max(id) + 1) and the next record has a hash
-- to chain from.
SELECT CAST(coalesce(max(a.id), 0) AS INTEGER) FROM audit_log a
WHERE a.ts < sqlc.arg(before) AND a.id < (SELECT max(m.id) FROM audit_log m);

-- name: DeleteAuditThrough :execrows
DELETE FROM audit_log WHERE id <= ?;

-- name: ListAuditArchive :many
SELECT * FROM audit_archive ORDER BY first_id;

-- name: LastAuditArchive :one
SELECT * FROM audit_archive ORDER BY first_id DESC LIMIT 1;

-- name: InsertAuditArchive :exec
INSERT INTO audit_archive (first_id, last_id, records, first_ts, last_ts, prev_hash, last_hash, data, data_sha256, archived_at, mac)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SetAuditArchiveMac :exec
UPDATE audit_archive SET mac = ? WHERE first_id = ? AND mac IS NULL;

-- name: GetAuditChain :one
SELECT * FROM audit_chain WHERE version = 2;

-- name: InsertAuditChain :exec
INSERT INTO audit_chain (version, from_id, key_enc, key_id, created_at) VALUES (2, ?, ?, ?, ?);

-- name: NextAuditID :one
-- The id the next record gets: past every hot and archived record.
SELECT CAST(max(coalesce((SELECT max(id) FROM audit_log), 0), coalesce((SELECT max(last_id) FROM audit_archive), 0)) + 1 AS INTEGER);

-- name: ExpirableAuditArchives :many
SELECT first_id FROM audit_archive WHERE data IS NOT NULL AND last_ts < ? ORDER BY first_id;

-- name: ExpireAuditArchive :exec
UPDATE audit_archive SET data = NULL, expired_at = ? WHERE first_id = ?;
