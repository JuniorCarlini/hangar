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
