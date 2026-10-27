-- Backups (docs/09).

-- name: ListBackupRecipients :many
SELECT * FROM backup_recipients ORDER BY created_at;

-- name: GetBackupRecipient :one
SELECT * FROM backup_recipients WHERE id = ?;

-- name: CreateBackupRecipient :exec
INSERT INTO backup_recipients (id, label, age_public_key, confirm_hash, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: ConfirmBackupRecipient :exec
UPDATE backup_recipients SET confirmed_at = ? WHERE id = ?;

-- name: DeleteBackupRecipient :execrows
DELETE FROM backup_recipients WHERE id = ?;

-- name: ListBackupTargets :many
SELECT * FROM backup_targets ORDER BY is_primary DESC, created_at;

-- name: GetBackupTarget :one
SELECT * FROM backup_targets WHERE id = ?;

-- name: CreateBackupTarget :exec
INSERT INTO backup_targets (id, name, provider, config_enc, lock_mode, object_lock_days, is_primary, checked_at, created_by, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: SetBackupTargetCheck :exec
UPDATE backup_targets SET checked_at = ?, check_error = ? WHERE id = ?;

-- name: DeleteBackupTarget :execrows
DELETE FROM backup_targets WHERE id = ?;

-- name: GetBackupPolicy :one
SELECT * FROM backup_policies WHERE id = ?;

-- name: GetBackupPolicyByService :one
SELECT * FROM backup_policies WHERE service_id = ?;

-- name: ListBackupPolicies :many
SELECT * FROM backup_policies ORDER BY created_at;

-- name: UpsertBackupPolicy :exec
INSERT INTO backup_policies (id, service_id, enabled, every_hours, at_minute, wal, wal_since, next_run_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    enabled = excluded.enabled, every_hours = excluded.every_hours, at_minute = excluded.at_minute,
    wal = excluded.wal, wal_since = excluded.wal_since, next_run_at = excluded.next_run_at,
    updated_at = excluded.updated_at;

-- name: SetBackupPolicyNextRun :exec
UPDATE backup_policies SET next_run_at = ? WHERE id = ?;

-- name: WALEnabled :one
SELECT count(*) FROM backup_policies WHERE service_id = ? AND enabled = 1 AND wal = 1;

-- name: CreateBackupRun :exec
INSERT INTO backup_runs (id, service_id, label, kind, trigger, class, status, created_by, started_at)
VALUES (?, ?, ?, ?, ?, ?, 'running', ?, ?);

-- name: FinishBackupRun :exec
UPDATE backup_runs SET
    status = ?, object_key = ?, size_bytes = ?, sha256 = ?, verified = ?, check_json = ?,
    uploads_json = ?, warning = ?, error = ?, finished_at = ?
WHERE id = ?;

-- name: GetBackupRun :one
SELECT * FROM backup_runs WHERE id = ?;

-- name: ListBackupRuns :many
SELECT * FROM backup_runs ORDER BY started_at DESC LIMIT ?;

-- name: ListServiceBackupRuns :many
SELECT * FROM backup_runs WHERE service_id = ? ORDER BY started_at DESC LIMIT ?;

-- name: LastOKBackupRun :one
SELECT * FROM backup_runs
WHERE label = ? AND kind = ? AND status = 'ok'
ORDER BY started_at DESC LIMIT 1;

-- name: LastBackupRun :one
SELECT * FROM backup_runs WHERE label = ? AND kind = ? ORDER BY started_at DESC LIMIT 1;

-- name: CountOKRunsInClassSince :one
SELECT count(*) FROM backup_runs
WHERE label = ? AND kind = ? AND class = ? AND status = 'ok' AND started_at >= ?;

-- name: FailRunningBackupRuns :exec
UPDATE backup_runs SET status = 'failed', error = ?, finished_at = ? WHERE status = 'running';

-- name: PruneBackupRuns :exec
DELETE FROM backup_runs WHERE started_at < ?;

-- name: GetWALStatus :one
SELECT * FROM wal_status WHERE service_id = ?;

-- name: UpsertWALStatus :exec
INSERT INTO wal_status (service_id, last_archived_wal, last_archived_at, pending, oldest_pending_at, last_error, checked_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (service_id) DO UPDATE SET
    last_archived_wal = excluded.last_archived_wal, last_archived_at = excluded.last_archived_at,
    pending = excluded.pending, oldest_pending_at = excluded.oldest_pending_at,
    last_error = excluded.last_error, checked_at = excluded.checked_at;

-- name: CreateBackupRestore :exec
INSERT INTO backup_restores (id, service_id, label, mode, point, destination, new_service, status, step, created_by, started_at)
VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?, ?, ?);

-- name: SetBackupRestoreStep :exec
UPDATE backup_restores SET step = ? WHERE id = ?;

-- name: FinishBackupRestore :exec
UPDATE backup_restores SET status = ?, error = ?, finished_at = ? WHERE id = ?;

-- name: ListServiceRestores :many
SELECT * FROM backup_restores WHERE service_id = ? ORDER BY started_at DESC LIMIT ?;

-- name: ListRestores :many
SELECT * FROM backup_restores ORDER BY started_at DESC LIMIT ?;

-- name: FailRunningRestores :exec
UPDATE backup_restores SET status = 'failed', error = ?, finished_at = ? WHERE status = 'running';

-- name: MaxAuditID :one
SELECT CAST(coalesce(max(id), 0) AS INTEGER) FROM audit_log;

-- name: GetBackupServerKey :one
SELECT identity_enc FROM backup_server_key WHERE id = 'server';

-- name: CreateBackupServerKey :exec
INSERT INTO backup_server_key (id, identity_enc, created_at) VALUES ('server', ?, ?)
ON CONFLICT (id) DO NOTHING;
