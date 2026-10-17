-- name: UpsertMetric :exec
INSERT OR REPLACE INTO metrics (key, resolution, ts, cpu_pct, mem_bytes, mem_limit, net_rx, net_tx, disk_used, disk_total)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: RollupMetricHours :exec
-- Hourly averages from the minute rows since the given time. Re-running it
-- replaces the hours it covers, so a partial current hour is fine.
INSERT OR REPLACE INTO metrics (key, resolution, ts, cpu_pct, mem_bytes, mem_limit, net_rx, net_tx, disk_used, disk_total)
SELECT m.key, '1h', m.ts - m.ts % 3600,
       avg(m.cpu_pct), CAST(avg(m.mem_bytes) AS INTEGER), max(m.mem_limit),
       avg(m.net_rx), avg(m.net_tx), CAST(avg(m.disk_used) AS INTEGER), max(m.disk_total)
FROM metrics m
WHERE m.resolution = '1m' AND m.ts >= sqlc.arg(since)
GROUP BY m.key, m.ts - m.ts % 3600;

-- name: DeleteMetricsBefore :exec
DELETE FROM metrics WHERE resolution = ? AND ts < ?;

-- name: ListMetrics :many
SELECT ts, cpu_pct, mem_bytes, mem_limit, net_rx, net_tx, disk_used, disk_total
FROM metrics
WHERE key = ? AND resolution = ? AND ts >= ?
ORDER BY ts;
