-- name: CreateAlertChannel :exec
INSERT INTO alert_channels (id, kind, name, target, min_severity, enabled, config_enc, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?);

-- name: ListAlertChannels :many
SELECT * FROM alert_channels ORDER BY created_at, id;

-- name: GetAlertChannel :one
SELECT * FROM alert_channels WHERE id = ?;

-- name: SetAlertChannelEnabled :execrows
UPDATE alert_channels SET enabled = ?, updated_at = ? WHERE id = ?;

-- name: DeleteAlertChannel :execrows
DELETE FROM alert_channels WHERE id = ?;

-- name: ListAlertRules :many
SELECT * FROM alert_rules;

-- name: UpsertAlertRule :exec
INSERT INTO alert_rules (kind, enabled, threshold, updated_at) VALUES (?, ?, ?, ?)
ON CONFLICT (kind) DO UPDATE SET enabled = excluded.enabled, threshold = excluded.threshold, updated_at = excluded.updated_at;

-- name: LastAlertByKey :one
SELECT * FROM alerts WHERE dedup_key = ? ORDER BY id DESC LIMIT 1;

-- name: CountFiringSince :one
SELECT count(*) FROM alerts WHERE dedup_key = ? AND resolved = 0 AND created_at >= ?;

-- name: InsertAlert :one
INSERT INTO alerts (kind, severity, category, dedup_key, params_json, resolved, muted, created_at, last_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING id;

-- name: BumpAlertRepeat :exec
UPDATE alerts SET repeats = repeats + 1, last_at = ? WHERE id = ?;

-- name: RecentAlerts :many
-- The newest alerts; security ones only when asked for (admins and up).
SELECT * FROM alerts
WHERE category = 'server' OR CAST(sqlc.arg(with_security) AS INTEGER) = 1
ORDER BY id DESC
LIMIT sqlc.arg(lim);

-- name: LatestAlertID :one
SELECT CAST(COALESCE(MAX(id), 0) AS INTEGER) FROM alerts WHERE category = 'server' OR CAST(sqlc.arg(with_security) AS INTEGER) = 1;

-- name: GetAlertSeen :one
SELECT last_id FROM alert_seen WHERE user_id = ?;

-- name: SetAlertSeen :exec
INSERT INTO alert_seen (user_id, last_id) VALUES (?, ?)
ON CONFLICT (user_id) DO UPDATE SET last_id = MAX(alert_seen.last_id, excluded.last_id);

-- name: InsertAlertDelivery :exec
INSERT INTO alert_deliveries (alert_id, channel_id, channel_name, channel_kind, kind, status, attempts, error, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: RecentAlertDeliveries :many
SELECT * FROM alert_deliveries ORDER BY id DESC LIMIT ?;

-- name: CountChannelDeliveriesSince :one
SELECT count(*) FROM alert_deliveries WHERE channel_id = ? AND status = 'sent' AND kind <> 'test' AND created_at >= ?;

-- name: PruneAlerts :exec
DELETE FROM alerts WHERE created_at < ?;

-- name: PruneAlertDeliveries :exec
DELETE FROM alert_deliveries WHERE created_at < ?;

-- name: RememberLoginIP :execrows
-- Inserts the address when it is new; the row count says whether it was.
INSERT INTO login_ips (user_id, ip, first_at, last_at) VALUES (?, ?, ?, ?)
ON CONFLICT (user_id, ip) DO NOTHING;

-- name: TouchLoginIP :exec
UPDATE login_ips SET last_at = ? WHERE user_id = ? AND ip = ?;

-- name: DeleteAllSessions :execrows
-- Lockdown: every session of every user ends at once.
DELETE FROM sessions;
