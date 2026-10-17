-- name: CreateProject :exec
INSERT INTO projects (id, slug, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?);

-- name: ListProjects :many
SELECT p.id, p.slug, p.name, p.created_at,
       (SELECT count(*) FROM services s WHERE s.project_id = p.id) AS service_count
FROM projects p ORDER BY p.name;

-- name: GetProjectBySlug :one
SELECT * FROM projects WHERE slug = ?;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = ?;

-- name: CreateService :exec
INSERT INTO services (id, project_id, slug, image, internal_port, memory_bytes, nano_cpus, pids_limit,
                      read_only, command_json, template, stateful, health_json, cap_add_json, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListServices :many
SELECT * FROM services WHERE project_id = ? ORDER BY slug;

-- name: ListAllServices :many
SELECT s.*, p.slug AS project_slug FROM services s JOIN projects p ON p.id = s.project_id;

-- name: GetService :one
SELECT * FROM services WHERE project_id = ? AND slug = ?;

-- name: SetDesiredState :exec
UPDATE services SET desired_state = ?, updated_at = ? WHERE id = ?;

-- name: DeleteService :exec
DELETE FROM services WHERE id = ?;

-- name: UpsertEnv :exec
INSERT INTO env_vars (service_id, key, value_enc, secret, updated_at) VALUES (?, ?, ?, ?, ?)
ON CONFLICT (service_id, key) DO UPDATE SET value_enc = excluded.value_enc, secret = excluded.secret, updated_at = excluded.updated_at;

-- name: ListEnv :many
SELECT * FROM env_vars WHERE service_id = ? ORDER BY key;

-- name: GetEnv :one
SELECT * FROM env_vars WHERE service_id = ? AND key = ?;

-- name: DeleteEnv :execrows
DELETE FROM env_vars WHERE service_id = ? AND key = ?;

-- name: CreateDeployment :exec
INSERT INTO deployments (id, service_id, status, image, env_hash, trigger, created_by, started_at)
VALUES (?, ?, 'running', ?, ?, ?, ?, ?);

-- name: FinishDeployment :exec
UPDATE deployments SET status = ?, error = ?, finished_at = ? WHERE id = ?;

-- name: SupersedeLive :exec
UPDATE deployments SET status = 'superseded' WHERE service_id = ? AND status = 'live' AND id != ?;

-- name: ListDeployments :many
SELECT * FROM deployments WHERE service_id = ? ORDER BY started_at DESC, rowid DESC LIMIT ?;

-- name: LastLiveDeployment :one
SELECT * FROM deployments WHERE service_id = ? AND status = 'live' ORDER BY started_at DESC, rowid DESC LIMIT 1;

-- name: HasRunningDeployment :one
SELECT count(*) FROM deployments WHERE service_id = ? AND status = 'running';

-- name: ListRunningDeployments :many
-- Deploys a previous hangard left half-way (killed, crashed, host reboot).
SELECT d.id, d.service_id, s.slug AS service_slug, p.slug AS project_slug
FROM deployments d
JOIN services s ON s.id = d.service_id
JOIN projects p ON p.id = s.project_id
WHERE d.status = 'running'
ORDER BY d.started_at;

-- name: SetDeploymentProgress :exec
UPDATE deployments SET phase = ?, log = ? WHERE id = ?;

-- name: SetDeploymentImageRef :exec
UPDATE deployments SET image_ref = ? WHERE id = ?;

-- name: GetDeployment :one
SELECT * FROM deployments WHERE id = ? AND service_id = ?;

-- name: SetServiceDeploySettings :exec
UPDATE services SET predeploy_json = ?, health_path = ?, validate_json = ?, validate_timeout_s = ?, updated_at = ? WHERE id = ?;

-- name: SetServiceMaintenance :exec
UPDATE services SET maintenance = ?, updated_at = ? WHERE id = ?;

-- name: SetCanvasPosition :exec
UPDATE services SET canvas_x = ?, canvas_y = ? WHERE id = ?;

-- name: ResetCanvasPositions :exec
UPDATE services SET canvas_x = NULL, canvas_y = NULL WHERE project_id = ?;
