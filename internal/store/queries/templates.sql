-- name: AddVolume :exec
INSERT INTO service_volumes (service_id, name, path) VALUES (?, ?, ?);

-- name: ListVolumes :many
SELECT * FROM service_volumes WHERE service_id = ? ORDER BY name;

-- name: UpsertExport :exec
INSERT INTO service_exports (service_id, key, value_enc, secret) VALUES (?, ?, ?, ?)
ON CONFLICT (service_id, key) DO UPDATE SET value_enc = excluded.value_enc, secret = excluded.secret;

-- name: ListExports :many
SELECT * FROM service_exports WHERE service_id = ? ORDER BY key;

-- name: CreatePort :exec
INSERT INTO ports (id, service_id, host_port, container_port, protocol, access, allowed_ips, expires_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: DeletePort :one
DELETE FROM ports WHERE id = ? AND service_id = ? RETURNING host_port;

-- name: ListPorts :many
SELECT * FROM ports WHERE service_id = ? ORDER BY host_port;

-- name: ListAllPorts :many
SELECT pt.*, s.slug AS service_slug, p.slug AS project_slug
FROM ports pt JOIN services s ON s.id = pt.service_id JOIN projects p ON p.id = s.project_id
ORDER BY pt.host_port;

-- name: PortInUse :one
SELECT count(*) FROM ports WHERE host_port = ? AND protocol = ?;

-- name: ExpiredPorts :many
SELECT pt.id, pt.service_id, pt.host_port, s.slug AS service_slug, p.slug AS project_slug
FROM ports pt JOIN services s ON s.id = pt.service_id JOIN projects p ON p.id = s.project_id
WHERE pt.expires_at IS NOT NULL AND pt.expires_at <= ?;

-- name: LinkProjects :exec
INSERT INTO project_links (project_a, project_b, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING;

-- name: UnlinkProjects :execrows
DELETE FROM project_links WHERE project_a = ? AND project_b = ?;

-- name: LinkedProjects :many
SELECT p.* FROM projects p
WHERE p.id IN (SELECT l1.project_b FROM project_links l1 WHERE l1.project_a = sqlc.arg(id)
               UNION SELECT l2.project_a FROM project_links l2 WHERE l2.project_b = sqlc.arg(id))
ORDER BY p.slug;

-- name: ListAllPortsWithOwner :many
SELECT pt.*, s.slug AS service_slug, p.slug AS project_slug, coalesce(u.email, '') AS owner_email
FROM ports pt JOIN services s ON s.id = pt.service_id JOIN projects p ON p.id = s.project_id
LEFT JOIN users u ON u.id = pt.created_by
ORDER BY pt.host_port;

-- name: DeleteVolume :execrows
DELETE FROM service_volumes WHERE service_id = ? AND name = ?;
