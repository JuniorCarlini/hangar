-- name: FindDependencyFinding :one
SELECT * FROM dependency_findings
WHERE coalesce(service_id, '') = sqlc.arg(service_key) AND target = sqlc.arg(target) AND ecosystem = sqlc.arg(ecosystem)
  AND package = sqlc.arg(package) AND advisory_id = sqlc.arg(advisory_id) AND kind = sqlc.arg(kind);

-- name: InsertDependencyFinding :exec
INSERT INTO dependency_findings (id, service_id, target, ecosystem, package, current_version, latest_version,
    fixed_version, severity, level, advisory_id, aliases, summary, source, kind, first_seen_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: RefreshDependencyFinding :exec
-- Seen again: new versions and severity, reopened if it had been resolved
-- (reopening clears notified_at so it is warned about again).
UPDATE dependency_findings
SET current_version = ?, latest_version = ?, fixed_version = ?, severity = ?, level = ?, aliases = ?,
    summary = ?, source = ?, last_seen_at = ?,
    notified_at = CASE WHEN resolved_at IS NULL THEN notified_at END,
    resolved_at = NULL
WHERE id = ?;

-- name: ResolveDependencyFindings :execrows
-- Findings of a target (of the given kinds) not seen in the scan that
-- started at seen_before.
-- (Plain placeholders: sqlc numbers named ones, which breaks next to a slice.)
UPDATE dependency_findings SET resolved_at = ?
WHERE coalesce(service_id, '') = ? AND target = ?
  AND resolved_at IS NULL AND last_seen_at < ? AND kind IN (sqlc.slice(kinds));

-- name: ListOpenDependencyFindings :many
SELECT f.*, coalesce(s.slug, '') AS service_slug, coalesce(p.slug, '') AS project_slug
FROM dependency_findings f
LEFT JOIN services s ON s.id = f.service_id
LEFT JOIN projects p ON p.id = s.project_id
WHERE f.resolved_at IS NULL
ORDER BY CASE f.level WHEN 'critical' THEN 0 WHEN 'security' THEN 1 WHEN 'minor' THEN 2 ELSE 3 END,
         p.slug, s.slug, f.package;

-- name: GetDependencyFinding :one
SELECT * FROM dependency_findings WHERE id = ?;

-- name: MarkDependencyFindingsNotified :exec
UPDATE dependency_findings SET notified_at = ? WHERE id IN (sqlc.slice(ids));

-- name: InsertFindingIgnore :exec
INSERT INTO finding_ignores (id, service_id, target, package, advisory_id, until_version, until_at, reason, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListFindingIgnores :many
SELECT i.*, coalesce(s.slug, '') AS service_slug, coalesce(p.slug, '') AS project_slug
FROM finding_ignores i
LEFT JOIN services s ON s.id = i.service_id
LEFT JOIN projects p ON p.id = s.project_id
WHERE i.until_at IS NULL OR i.until_at > sqlc.arg(now)
ORDER BY i.created_at DESC;

-- name: DeleteFindingIgnore :execrows
DELETE FROM finding_ignores WHERE id = ?;

-- name: DeleteExpiredFindingIgnores :exec
DELETE FROM finding_ignores WHERE until_at IS NOT NULL AND until_at <= ?;

-- name: UpsertDependencyScan :exec
INSERT INTO dependency_scans (target_key, scanned_at, packages, error) VALUES (?, ?, ?, ?)
ON CONFLICT (target_key) DO UPDATE SET scanned_at = excluded.scanned_at, packages = excluded.packages, error = excluded.error;

-- name: ListDependencyScans :many
SELECT * FROM dependency_scans;

-- name: ListLiveServiceImages :many
-- Every service with its current image and the exact reference that went
-- live (digest), for the inventory.
SELECT s.id, s.slug, p.slug AS project_slug, s.image, s.desired_state,
       CAST(coalesce((SELECT d.image_ref FROM deployments d WHERE d.service_id = s.id AND d.status = 'live'
                      ORDER BY d.started_at DESC LIMIT 1), '') AS TEXT) AS image_ref
FROM services s JOIN projects p ON p.id = s.project_id
ORDER BY p.slug, s.slug;
