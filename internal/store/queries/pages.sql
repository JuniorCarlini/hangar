-- Keyset pages of the lists that grow (internal/keyset, docs/20). Each
-- list has an "older" query (rows strictly below the cursor, newest first)
-- and a "newer" one (strictly above it, oldest first), both in the same
-- stable order: time, then a unique tie-breaker.

-- name: DeploymentsOlder :many
SELECT * FROM deployments
WHERE service_id = sqlc.arg(service_id)
  AND (started_at < sqlc.arg(at) OR (started_at = sqlc.arg(at) AND id < sqlc.arg(id)))
ORDER BY started_at DESC, id DESC LIMIT sqlc.arg(lim);

-- name: DeploymentsNewer :many
SELECT * FROM deployments
WHERE service_id = sqlc.arg(service_id)
  AND (started_at > sqlc.arg(at) OR (started_at = sqlc.arg(at) AND id > sqlc.arg(id)))
ORDER BY started_at, id LIMIT sqlc.arg(lim);

-- name: AlertsOlder :many
SELECT * FROM alerts
WHERE (category = 'server' OR CAST(sqlc.arg(with_security) AS INTEGER) = 1) AND id < sqlc.arg(before_id)
ORDER BY id DESC LIMIT sqlc.arg(lim);

-- name: AlertsNewer :many
SELECT * FROM alerts
WHERE (category = 'server' OR CAST(sqlc.arg(with_security) AS INTEGER) = 1) AND id > sqlc.arg(after_id)
ORDER BY id LIMIT sqlc.arg(lim);

-- name: AlertDeliveriesOlder :many
SELECT * FROM alert_deliveries WHERE id < sqlc.arg(before_id) ORDER BY id DESC LIMIT sqlc.arg(lim);

-- name: AlertDeliveriesNewer :many
SELECT * FROM alert_deliveries WHERE id > sqlc.arg(after_id) ORDER BY id LIMIT sqlc.arg(lim);

-- name: BackupRunsOlder :many
-- All runs (service_key '') or one service's.
SELECT * FROM backup_runs
WHERE (CAST(sqlc.arg(service_key) AS TEXT) = '' OR service_id = sqlc.arg(service_key))
  AND (started_at < sqlc.arg(at) OR (started_at = sqlc.arg(at) AND id < sqlc.arg(id)))
ORDER BY started_at DESC, id DESC LIMIT sqlc.arg(lim);

-- name: BackupRunsNewer :many
SELECT * FROM backup_runs
WHERE (CAST(sqlc.arg(service_key) AS TEXT) = '' OR service_id = sqlc.arg(service_key))
  AND (started_at > sqlc.arg(at) OR (started_at = sqlc.arg(at) AND id > sqlc.arg(id)))
ORDER BY started_at, id LIMIT sqlc.arg(lim);

-- name: AsksOlder :many
-- Certificate decisions, all (decision '') or one kind. The tie-breaker
-- is the row's primary key as text.
SELECT * FROM tls_ask_log
WHERE (CAST(sqlc.arg(decision) AS TEXT) = '' OR decision = sqlc.arg(decision))
  AND (last_at < sqlc.arg(at) OR (last_at = sqlc.arg(at) AND (hostname || '|' || decision || '|' || hour) < sqlc.arg(id)))
ORDER BY last_at DESC, (hostname || '|' || decision || '|' || hour) DESC LIMIT sqlc.arg(lim);

-- name: AsksNewer :many
SELECT * FROM tls_ask_log
WHERE (CAST(sqlc.arg(decision) AS TEXT) = '' OR decision = sqlc.arg(decision))
  AND (last_at > sqlc.arg(at) OR (last_at = sqlc.arg(at) AND (hostname || '|' || decision || '|' || hour) > sqlc.arg(id)))
ORDER BY last_at, (hostname || '|' || decision || '|' || hour) LIMIT sqlc.arg(lim);
