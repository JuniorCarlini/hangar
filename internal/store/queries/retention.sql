-- Retention (docs/20). Every prune deletes at most sqlc.arg(lim) rows, so
-- the janitor holds the single write lock for milliseconds and runs again
-- until a batch comes back short.

-- name: MetricKeys :many
SELECT DISTINCT key FROM metrics;

-- name: PruneMetricKey :execrows
-- One key at a time walks the primary key (key, resolution, ts) instead
-- of scanning the whole table.
DELETE FROM metrics
WHERE metrics.key = sqlc.arg(key) AND metrics.resolution = sqlc.arg(resolution) AND metrics.ts IN (
    SELECT m.ts FROM metrics m
    WHERE m.key = sqlc.arg(key) AND m.resolution = sqlc.arg(resolution) AND m.ts < sqlc.arg(before)
    ORDER BY m.ts LIMIT sqlc.arg(lim)
);

-- name: PruneTLSAsks :execrows
-- Denials are noise once they stop (docs/03): a week is enough to see an
-- attack and block it. Approvals stay longer: a domain approved before
-- renews without counting against the hourly cap.
DELETE FROM tls_ask_log
WHERE (tls_ask_log.hostname, tls_ask_log.decision, tls_ask_log.hour) IN (
    SELECT a.hostname, a.decision, a.hour FROM tls_ask_log a
    WHERE (a.decision = 'deny' AND a.hour < sqlc.arg(deny_before)) OR a.hour < sqlc.arg(allow_before)
    LIMIT sqlc.arg(lim)
);

-- name: PruneTLSApprovals :execrows
-- An approval not renewed within the approval retention is forgotten: the
-- name counts as new again (and against the hourly cap) if it comes back.
DELETE FROM tls_approvals
WHERE tls_approvals.hostname IN (
    SELECT a.hostname FROM tls_approvals a WHERE a.last_hour < sqlc.arg(before) LIMIT sqlc.arg(lim)
);

-- name: PruneAlertRows :execrows
-- Alerts whose last occurrence is past retention. A server alert still
-- firing (the newest row of its key, not resolved) is kept: it is the
-- state the "back to normal" notice resolves; past stale_before it is
-- dropped anyway. Security alerts have no resolution and just age out.
DELETE FROM alerts
WHERE alerts.id IN (
    SELECT a.id FROM alerts a
    WHERE a.last_at < sqlc.arg(before)
      AND (a.resolved = 1 OR a.category = 'security' OR a.last_at < sqlc.arg(stale_before)
           OR EXISTS (SELECT 1 FROM alerts b WHERE b.dedup_key = a.dedup_key AND b.id > a.id))
    ORDER BY a.id LIMIT sqlc.arg(lim)
);

-- name: PruneAlertDeliveryRows :execrows
DELETE FROM alert_deliveries
WHERE alert_deliveries.id IN (SELECT x.id FROM alert_deliveries x WHERE x.created_at < sqlc.arg(before) ORDER BY x.id LIMIT sqlc.arg(lim));

-- name: PruneDeploymentRows :execrows
-- Keeps the newest skip + 1 deploys of each service (skip is the OFFSET
-- of the oldest one kept; deploys started in the same second as it stay
-- too). Running and live deploys are never removed, whatever their age.
DELETE FROM deployments
WHERE deployments.id IN (
    SELECT d.id FROM deployments d
    WHERE d.status NOT IN ('running', 'live')
      AND d.started_at < (
          SELECT n.started_at FROM deployments n WHERE n.service_id = d.service_id
          ORDER BY n.started_at DESC LIMIT 1 OFFSET CAST(sqlc.arg(skip) AS INTEGER))
    LIMIT sqlc.arg(lim)
);

-- name: TrimDeploymentLogs :execrows
-- Deploys past the newest skip + 1 of their service keep their row
-- (status, image, commit, error) but drop the build log, the only large
-- column.
UPDATE deployments SET log = ''
WHERE deployments.id IN (
    SELECT d.id FROM deployments d
    WHERE d.log != '' AND d.status != 'running'
      AND d.started_at < (
          SELECT n.started_at FROM deployments n WHERE n.service_id = d.service_id
          ORDER BY n.started_at DESC LIMIT 1 OFFSET CAST(sqlc.arg(skip) AS INTEGER))
    LIMIT sqlc.arg(lim)
);

-- name: PruneBackupRunRows :execrows
-- A run's record lives as long as its object can still be in the bucket
-- (the lifecycle days of its folder, one cutoff per folder from the
-- caller) plus a grace for the history; a failed run has no object.
-- The newest run of each label and kind is always kept: it is what the
-- panel shows as "last backup".
DELETE FROM backup_runs
WHERE backup_runs.id IN (
    SELECT r.id FROM backup_runs r
    WHERE r.status != 'running'
      AND r.started_at < CASE
            WHEN r.status = 'failed' THEN sqlc.arg(failed_before)
            WHEN r.class = 'daily' THEN sqlc.arg(daily_before)
            WHEN r.class = 'weekly' THEN sqlc.arg(weekly_before)
            WHEN r.kind = 'panel' THEN sqlc.arg(panel_before)
            WHEN r.kind = 'pg_base' THEN sqlc.arg(base_before)
            ELSE sqlc.arg(other_before) END
      AND EXISTS (SELECT 1 FROM backup_runs n WHERE n.label = r.label AND n.kind = r.kind AND n.started_at > r.started_at)
    LIMIT sqlc.arg(lim)
);

-- name: PruneBackupRestoreRows :execrows
DELETE FROM backup_restores
WHERE backup_restores.id IN (SELECT x.id FROM backup_restores x WHERE x.status != 'running' AND x.started_at < sqlc.arg(before) LIMIT sqlc.arg(lim));

-- name: PruneProjectRestoreRows :execrows
-- The latest restore of each project stays: the project page shows it.
DELETE FROM project_restores
WHERE project_restores.id IN (
    SELECT r.id FROM project_restores r
    WHERE r.status != 'running' AND r.started_at < sqlc.arg(before)
      AND EXISTS (SELECT 1 FROM project_restores n WHERE n.project_id = r.project_id AND n.started_at > r.started_at)
    LIMIT sqlc.arg(lim)
);

-- name: PruneResolvedFindings :execrows
-- Findings fixed long ago; a finding that comes back is a new row (and a
-- new notice).
DELETE FROM dependency_findings
WHERE dependency_findings.id IN (
    SELECT x.id FROM dependency_findings x
    WHERE x.resolved_at IS NOT NULL AND x.resolved_at < sqlc.arg(before)
    LIMIT sqlc.arg(lim)
);

-- name: PruneFindingIgnoreRows :execrows
DELETE FROM finding_ignores
WHERE finding_ignores.id IN (SELECT x.id FROM finding_ignores x WHERE x.until_at IS NOT NULL AND x.until_at <= sqlc.arg(now) LIMIT sqlc.arg(lim));

-- name: PruneImageProbeRows :execrows
DELETE FROM image_probes
WHERE image_probes.digest IN (SELECT x.digest FROM image_probes x WHERE x.probed_at < sqlc.arg(before) LIMIT sqlc.arg(lim));

-- name: PruneWebhookDeliveryRows :execrows
DELETE FROM webhook_deliveries
WHERE webhook_deliveries.delivery_id IN (SELECT x.delivery_id FROM webhook_deliveries x WHERE x.received_at < sqlc.arg(before) LIMIT sqlc.arg(lim));

-- name: PruneLoginIPs :execrows
-- A known IP not used for this long is new again (and alerts again).
DELETE FROM login_ips
WHERE (login_ips.user_id, login_ips.ip) IN (SELECT x.user_id, x.ip FROM login_ips x WHERE x.last_at < sqlc.arg(before) LIMIT sqlc.arg(lim));

-- name: PruneInvites :execrows
-- Invites used or expired a while ago (the team page lists only open ones).
DELETE FROM invites
WHERE invites.id IN (
    SELECT x.id FROM invites x
    WHERE (x.used_at IS NOT NULL AND x.used_at < sqlc.arg(before)) OR x.expires_at < sqlc.arg(before)
    LIMIT sqlc.arg(lim)
);

-- name: PruneLogMarks :execrows
-- Marks point into container logs, which Docker rotates long before this.
DELETE FROM log_marks
WHERE log_marks.id IN (SELECT x.id FROM log_marks x WHERE x.at < sqlc.arg(before_ns) LIMIT sqlc.arg(lim));
