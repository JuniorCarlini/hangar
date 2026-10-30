-- name: CreateDomain :exec
INSERT INTO domains (id, service_id, endpoint_id, hostname, created_at) VALUES (?, ?, ?, ?, ?);

-- name: DeleteDomain :one
DELETE FROM domains WHERE id = ? AND service_id = ? RETURNING hostname, endpoint_id;

-- name: CountDomainsOnEndpoint :one
SELECT count(*) FROM domains WHERE endpoint_id = ?;

-- name: CountDomains :one
SELECT count(*) FROM domains WHERE service_id = ?;

-- name: GetServiceByID :one
SELECT * FROM services WHERE id = ?;

-- name: ListDomains :many
SELECT * FROM domains WHERE service_id = ? ORDER BY hostname;

-- name: ListAllDomains :many
SELECT d.hostname, s.id AS service_id, s.slug AS service_slug, p.slug AS project_slug,
       s.internal_port, e.port AS endpoint_port, s.maintenance
FROM domains d JOIN services s ON s.id = d.service_id JOIN projects p ON p.id = s.project_id
LEFT JOIN endpoints e ON e.id = d.endpoint_id
-- A domain on an endpoint that is internal is not served (the panel keeps
-- this from happening; this is the last line). Nor is an older domain left
-- unbound on a service without a port: it would route to port 0.
WHERE (d.endpoint_id IS NULL AND s.internal_port > 0) OR e.public = 1
ORDER BY d.hostname;

-- name: GetDomainByHostname :one
SELECT * FROM domains WHERE hostname = ?;

-- name: DynamicService :one
SELECT s.*, p.slug AS project_slug FROM services s JOIN projects p ON p.id = s.project_id
WHERE s.dynamic_domains = 1;

-- name: SetDynamicDomains :exec
UPDATE services SET dynamic_domains = ?, domain_check_path = ?, domain_check_secret_enc = ?, updated_at = ? WHERE id = ?;

-- name: BlockHostname :exec
INSERT INTO domain_blocklist (hostname, reason, created_by, created_at) VALUES (?, ?, ?, ?)
ON CONFLICT (hostname) DO UPDATE SET reason = excluded.reason;

-- name: UnblockHostname :execrows
DELETE FROM domain_blocklist WHERE hostname = ?;

-- name: IsBlocked :one
SELECT count(*) FROM domain_blocklist WHERE hostname = ?;

-- name: ListBlocked :many
SELECT * FROM domain_blocklist ORDER BY created_at DESC;

-- name: LogAsk :exec
INSERT INTO tls_ask_log (hostname, decision, reason, hour, count, last_at, via) VALUES (?, ?, ?, ?, 1, ?, ?)
ON CONFLICT (hostname, decision, hour) DO UPDATE SET count = count + 1, reason = excluded.reason, last_at = excluded.last_at, via = excluded.via;

-- name: SetDomainRequireTXT :exec
UPDATE services SET domain_require_txt = ?, updated_at = ? WHERE id = ?;

-- name: CountNewApprovalsSince :one
-- Hostnames approved for the first time since an hour (the hourly cap).
SELECT count(*) FROM tls_approvals WHERE first_hour >= ?;

-- name: RecentAsks :many
SELECT * FROM tls_ask_log ORDER BY last_at DESC LIMIT ?;

-- name: CountAskRows :one
SELECT count(*) FROM tls_ask_log;

-- name: WasApproved :one
SELECT count(*) FROM tls_approvals WHERE hostname = ?;

-- name: RecordApproval :exec
INSERT INTO tls_approvals (hostname, first_hour, last_hour) VALUES (sqlc.arg(hostname), sqlc.arg(hour), sqlc.arg(hour))
ON CONFLICT (hostname) DO UPDATE SET last_hour = max(tls_approvals.last_hour, excluded.last_hour);

-- name: CountApprovedHosts :one
SELECT count(*) FROM tls_approvals;

-- name: BumpAsk :exec
-- The counter of a row that already exists (the log is at its ceiling).
UPDATE tls_ask_log SET count = count + 1, reason = ?, last_at = ?, via = ?
WHERE hostname = ? AND decision = ? AND hour = ?;

-- name: CountDeniedSince :one
SELECT coalesce(sum(count), 0) FROM tls_ask_log WHERE decision = 'deny' AND hour >= ?;

-- name: GetEdgeSettings :one
SELECT * FROM edge_settings WHERE id = 1;

-- name: UpsertEdgeSettings :exec
INSERT INTO edge_settings (id, base_domain, dns_provider, dns_token_enc, updated_by, updated_at)
VALUES (1, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    base_domain = excluded.base_domain, dns_provider = excluded.dns_provider,
    dns_token_enc = excluded.dns_token_enc, updated_by = excluded.updated_by,
    updated_at = excluded.updated_at;
