-- name: UpsertEnvSuggestions :exec
INSERT INTO service_env_suggestions (service_id, file, vars_json, digest, updated_at)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (service_id) DO UPDATE SET
    file = excluded.file, vars_json = excluded.vars_json, digest = excluded.digest, updated_at = excluded.updated_at;

-- name: GetEnvSuggestions :one
SELECT * FROM service_env_suggestions WHERE service_id = ?;

-- name: DeleteEnvSuggestions :exec
DELETE FROM service_env_suggestions WHERE service_id = ?;

-- name: DismissEnvSuggestions :execrows
UPDATE service_env_suggestions SET dismissed_digest = digest WHERE service_id = ?;
