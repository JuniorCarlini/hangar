-- name: UpsertEnvFile :exec
INSERT INTO service_env_files (service_id, text_enc, updated_at)
VALUES (?, ?, ?)
ON CONFLICT (service_id) DO UPDATE SET text_enc = excluded.text_enc, updated_at = excluded.updated_at;

-- name: GetEnvFile :one
SELECT text_enc FROM service_env_files WHERE service_id = ?;
