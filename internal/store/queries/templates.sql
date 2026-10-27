-- name: AddVolume :exec
INSERT INTO service_volumes (service_id, name, path, read_only, owner_service_id) VALUES (?, ?, ?, ?, ?);

-- name: ListVolumes :many
-- owner_slug is the service whose Docker volume this one is (empty: its own).
SELECT v.*, coalesce(o.slug, '') AS owner_slug
FROM service_volumes v LEFT JOIN services o ON o.id = v.owner_service_id
WHERE v.service_id = ? ORDER BY v.name;

-- name: ListVolumeSharers :many
-- The other services that mount a volume of this one.
SELECT v.name, s.slug AS service_slug
FROM service_volumes v JOIN services s ON s.id = v.service_id
WHERE v.owner_service_id = ? ORDER BY v.name, s.slug;

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

-- name: PortInUseByOther :one
SELECT count(*) FROM ports WHERE host_port = ? AND protocol = ? AND id <> ?;

-- name: UpdatePort :execrows
UPDATE ports SET host_port = ?, container_port = ?, protocol = ?, access = ?, allowed_ips = ?, expires_at = ?
WHERE id = ? AND service_id = ?;

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

-- name: AddOffer :exec
INSERT INTO service_offers (service_id, key) VALUES (?, ?) ON CONFLICT DO NOTHING;

-- name: DeleteOffer :exec
DELETE FROM service_offers WHERE service_id = ? AND key = ?;

-- name: ListOffers :many
SELECT key FROM service_offers WHERE service_id = ? ORDER BY key;

-- name: ListOfferedVars :many
-- The offered variables of a service, with their stored value.
SELECT e.* FROM env_vars e JOIN service_offers o ON o.service_id = e.service_id AND o.key = e.key
WHERE e.service_id = ? ORDER BY e.key;

-- name: UpdateVolumePath :execrows
UPDATE service_volumes SET path = ? WHERE service_id = ? AND name = ?;

-- name: AddVolumeTrash :exec
INSERT INTO volume_trash (service_id, name, created_at) VALUES (?, ?, ?)
ON CONFLICT (service_id, name) DO NOTHING;

-- name: ListVolumeTrash :many
SELECT name FROM volume_trash WHERE service_id = ? ORDER BY name;

-- name: DeleteVolumeTrash :exec
DELETE FROM volume_trash WHERE service_id = ? AND name = ?;
