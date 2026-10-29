-- name: CreateProject :exec
INSERT INTO projects (id, slug, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?);

-- name: ListProjects :many
SELECT p.id, p.slug, p.name, p.created_at,
       (SELECT count(*) FROM services s WHERE s.project_id = p.id) AS service_count
FROM projects p ORDER BY p.name;

-- name: GetProjectBySlug :one
SELECT * FROM projects WHERE slug = ?;

-- name: GetProjectByID :one
SELECT * FROM projects WHERE id = ?;

-- name: DeleteProject :exec
DELETE FROM projects WHERE id = ?;

-- name: CreateService :exec
INSERT INTO services (id, project_id, slug, image, internal_port, memory_bytes, nano_cpus, pids_limit,
                      read_only, command_json, template, stateful, health_json, cap_add_json, stop_grace_s, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

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
UPDATE services SET predeploy_json = ?, health_path = ?, validate_json = ?, validate_timeout_s = ?, startup_grace_s = ?, updated_at = ? WHERE id = ?;

-- name: SetServiceImage :execrows
-- Points the service at another image, only if it still runs the one the
-- caller saw (two changes at once, or a revert after someone else changed
-- it, must not overwrite each other).
UPDATE services SET image = sqlc.arg(image), updated_at = sqlc.arg(updated_at)
WHERE id = sqlc.arg(id) AND image = sqlc.arg(old_image);

-- name: SetServiceMaintenance :exec
UPDATE services SET maintenance = ?, updated_at = ? WHERE id = ?;

-- name: SetCanvasPosition :exec
UPDATE services SET canvas_x = ?, canvas_y = ? WHERE id = ?;

-- name: ResetCanvasPositions :exec
UPDATE services SET canvas_x = NULL, canvas_y = NULL WHERE project_id = ?;

-- name: KnowsProject :one
SELECT count(*) FROM projects WHERE id = ?;

-- name: KnowsService :one
SELECT count(*) FROM services WHERE id = ? AND project_id = ?;

-- name: PinProject :exec
INSERT INTO pinned_projects (user_id, project_id, pinned_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING;

-- name: UnpinProject :exec
DELETE FROM pinned_projects WHERE user_id = ? AND project_id = ?;

-- name: ListPinnedProjects :many
SELECT project_id FROM pinned_projects WHERE user_id = ? ORDER BY pinned_at, project_id;

-- name: SetServiceResources :exec
-- Memory and CPU the next deploy gives the container.
UPDATE services SET memory_bytes = ?, nano_cpus = ?, updated_at = ? WHERE id = ?;

-- name: SetServiceInternalPort :exec
UPDATE services SET internal_port = ?, updated_at = ? WHERE id = ?;
