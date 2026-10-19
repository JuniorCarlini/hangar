-- name: CreateVolumeLimit :execrows
INSERT INTO volume_limits (volume, project_id, service_id, name, size_bytes, state, step, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (volume) DO UPDATE SET
    project_id = excluded.project_id, service_id = excluded.service_id, name = excluded.name,
    size_bytes = excluded.size_bytes, state = excluded.state, step = excluded.step, error = '',
    restart_json = '[]', created_by = excluded.created_by, created_at = excluded.created_at,
    updated_at = excluded.updated_at
WHERE volume_limits.state = 'failed';

-- name: GetVolumeLimit :one
SELECT * FROM volume_limits WHERE volume = ?;

-- name: ListVolumeLimits :many
SELECT * FROM volume_limits ORDER BY volume;

-- name: SetVolumeLimitState :exec
UPDATE volume_limits SET state = ?, step = ?, error = ?, updated_at = ? WHERE volume = ?;

-- name: SetVolumeLimitError :exec
UPDATE volume_limits SET error = ?, updated_at = ? WHERE volume = ?;

-- name: SetVolumeLimitRestart :exec
UPDATE volume_limits SET restart_json = ?, updated_at = ? WHERE volume = ?;

-- name: GrowVolumeLimit :execrows
UPDATE volume_limits SET size_bytes = ?, error = '', updated_at = ?
WHERE volume = ? AND state = 'active' AND size_bytes < ?;

-- name: DeleteVolumeLimit :exec
DELETE FROM volume_limits WHERE volume = ?;

-- name: ServiceDesiredStates :many
SELECT id, slug, desired_state FROM services WHERE id IN (sqlc.slice('ids'));
