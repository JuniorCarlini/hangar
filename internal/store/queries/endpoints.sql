-- name: CreateEndpoint :exec
INSERT INTO endpoints (id, service_id, name, port, label, public, sslip_enabled, created_at, host_label)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListEndpoints :many
SELECT * FROM endpoints WHERE service_id = ? ORDER BY port;

-- name: GetEndpoint :one
SELECT * FROM endpoints WHERE id = ? AND service_id = ?;

-- name: DeleteEndpoint :exec
-- Never one with custom domains on it: the foreign key would delete them.
DELETE FROM endpoints WHERE endpoints.id = ? AND endpoints.service_id = ?
  AND NOT EXISTS (SELECT 1 FROM domains d WHERE d.endpoint_id = endpoints.id);

-- name: SetEndpointPublic :exec
UPDATE endpoints SET public = ? WHERE id = ? AND service_id = ?;

-- name: SetEndpointSslip :exec
-- The operator's own choice: no longer "switched off by a domain".
UPDATE endpoints SET sslip_enabled = ?, sslip_auto_off = 0 WHERE id = ? AND service_id = ?;

-- name: ListPublicEndpoints :many
SELECT e.id, e.service_id, e.name, e.port, e.label, e.sslip_enabled, e.host_label,
       s.slug AS service_slug, p.slug AS project_slug, s.maintenance
FROM endpoints e JOIN services s ON s.id = e.service_id JOIN projects p ON p.id = s.project_id
WHERE e.public = 1
ORDER BY p.slug, s.slug, e.port;

-- name: CountPublicEndpoints :one
SELECT count(*) FROM endpoints WHERE service_id = ? AND public = 1;

-- name: ListEndpointsWithoutHostLabel :many
SELECT e.id, e.name, s.slug AS service_slug, p.slug AS project_slug
FROM endpoints e JOIN services s ON s.id = e.service_id JOIN projects p ON p.id = s.project_id
WHERE e.host_label = ''
ORDER BY e.created_at, e.id;

-- name: HostLabelTaken :one
SELECT count(*) FROM endpoints WHERE host_label = ?;

-- name: SetEndpointHostLabel :exec
UPDATE endpoints SET host_label = ? WHERE id = ?;

-- name: SetEndpointSslipAutoOff :exec
UPDATE endpoints SET sslip_enabled = ?, sslip_auto_off = ? WHERE id = ? AND service_id = ?;

-- name: ListServicesWithoutEndpoints :many
SELECT s.id, s.project_id, s.slug, s.internal_port, s.template, p.slug AS project_slug
FROM services s JOIN projects p ON p.id = s.project_id
WHERE s.internal_port > 0
  AND NOT EXISTS (SELECT 1 FROM endpoints e WHERE e.service_id = s.id)
ORDER BY s.created_at, s.id;

-- name: ListUnboundDomainEndpoints :many
-- Domains older than endpoints (endpoint_id NULL) and the endpoint on their
-- service's own port, where they have always gone.
SELECT d.id AS domain_id, e.id AS endpoint_id, e.service_id, e.public, e.sslip_enabled
FROM domains d
JOIN services s ON s.id = d.service_id
JOIN endpoints e ON e.service_id = s.id AND e.port = s.internal_port
WHERE d.endpoint_id IS NULL;

-- name: BindDomainEndpoint :exec
UPDATE domains SET endpoint_id = ? WHERE id = ? AND endpoint_id IS NULL;

-- name: DomainUnderLabel :one
-- A custom domain whose first label is this one: an automatic link with it
-- could end up on the same hostname.
SELECT count(*) FROM domains WHERE hostname LIKE sqlc.arg(label) || '.%';
