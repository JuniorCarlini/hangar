-- name: ListServiceCommands :many
SELECT * FROM service_commands WHERE service_id = ? ORDER BY name, created_at;

-- name: GetServiceCommand :one
SELECT * FROM service_commands WHERE id = ? AND service_id = ?;

-- name: CountServiceCommands :one
SELECT COUNT(*) FROM service_commands WHERE service_id = ?;

-- name: CreateServiceCommand :exec
INSERT INTO service_commands (id, service_id, name, command, created_at) VALUES (?, ?, ?, ?, ?);

-- name: DeleteServiceCommand :one
DELETE FROM service_commands WHERE id = ? AND service_id = ? RETURNING name;
