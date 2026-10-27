-- name: CreateServiceGit :exec
INSERT INTO service_git (service_id, repo_url, branch, subdir, dockerfile, token_enc, credential_id, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetServiceGit :one
SELECT * FROM service_git WHERE service_id = ?;

-- name: UpdateServiceGitSource :exec
UPDATE service_git SET repo_url = ?, branch = ?, subdir = ?, dockerfile = ?, updated_at = ? WHERE service_id = ?;

-- name: SetServiceGitToken :exec
UPDATE service_git SET token_enc = ?, credential_id = NULL, updated_at = ? WHERE service_id = ?;

-- name: SetServiceGitCredential :exec
UPDATE service_git SET credential_id = ?, token_enc = NULL, updated_at = ? WHERE service_id = ?;

-- name: SetServiceGitWebhook :exec
UPDATE service_git SET webhook_token_hash = ?, webhook_token_enc = ?, webhook_secret_enc = ?, updated_at = ?
WHERE service_id = ?;

-- name: GetServiceGitByWebhook :one
SELECT g.*, s.slug AS service_slug, p.slug AS project_slug
FROM service_git g
JOIN services s ON s.id = g.service_id
JOIN projects p ON p.id = s.project_id
WHERE g.webhook_token_hash = ?;

-- name: ListProjectGitSources :many
SELECT g.service_id, g.repo_url, g.branch FROM service_git g
JOIN services s ON s.id = g.service_id WHERE s.project_id = ?;

-- name: RecordWebhookDelivery :execrows
INSERT INTO webhook_deliveries (delivery_id, service_id, received_at) VALUES (?, ?, ?)
ON CONFLICT (delivery_id) DO NOTHING;

-- name: PruneWebhookDeliveries :exec
DELETE FROM webhook_deliveries WHERE received_at < ?;

-- name: SetDeploymentCommit :exec
UPDATE deployments SET commit_sha = ?, commit_message = ? WHERE id = ?;

-- name: CreateGitCredential :exec
INSERT INTO git_credentials (id, project_id, name, host, token_enc, token_hint, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetGitCredential :one
SELECT * FROM git_credentials WHERE id = ?;

-- name: ListGitCredentials :many
SELECT c.id, c.project_id, c.name, c.host, c.token_hint, c.created_at, c.updated_at, c.last_used_at,
       COALESCE(p.slug, '') AS project_slug,
       (SELECT COUNT(*) FROM service_git g WHERE g.credential_id = c.id) AS uses
FROM git_credentials c
LEFT JOIN projects p ON p.id = c.project_id
ORDER BY c.project_id IS NOT NULL, p.slug, c.name;

-- name: UpdateGitCredentialToken :exec
UPDATE git_credentials SET token_enc = ?, token_hint = ?, updated_at = ? WHERE id = ?;

-- name: TouchGitCredential :exec
UPDATE git_credentials SET last_used_at = ? WHERE id = ?;

-- name: DeleteGitCredential :exec
DELETE FROM git_credentials WHERE id = ?;

-- name: ListGitCredentialUsers :many
SELECT p.slug AS project_slug, s.slug AS service_slug
FROM service_git g
JOIN services s ON s.id = g.service_id
JOIN projects p ON p.id = s.project_id
WHERE g.credential_id = ?
ORDER BY p.slug, s.slug;

-- name: SetServiceGitAuto :exec
UPDATE service_git SET auto_deploy = ?, auto_seen = ?, updated_at = ? WHERE service_id = ?;

-- name: SetServiceGitSeen :exec
UPDATE service_git SET auto_seen = ? WHERE service_id = ?;

-- name: ListAutoDeployServices :many
SELECT g.service_id, s.slug AS service_slug, p.slug AS project_slug
FROM service_git g
JOIN services s ON s.id = g.service_id
JOIN projects p ON p.id = s.project_id
WHERE g.auto_deploy = 1;
