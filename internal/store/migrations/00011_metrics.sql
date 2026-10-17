-- +goose Up
-- Aggregated resource usage (docs/06, docs/20). The last hour at 10 s lives
-- only in memory; here go 1-minute averages (kept 7 days) and 1-hour
-- averages (kept 90 days). key is "host" or the service id (or "ctr:<name>"
-- for a managed container without a service, like Caddy).
CREATE TABLE metrics (
    key        TEXT    NOT NULL,
    resolution TEXT    NOT NULL CHECK (resolution IN ('1m', '1h')),
    ts         INTEGER NOT NULL, -- unix seconds, start of the bucket
    cpu_pct    REAL    NOT NULL, -- host: of all cores; container: 100 = one core
    mem_bytes  INTEGER NOT NULL,
    mem_limit  INTEGER NOT NULL,
    net_rx     REAL    NOT NULL, -- bytes per second
    net_tx     REAL    NOT NULL,
    disk_used  INTEGER NOT NULL DEFAULT 0,
    disk_total INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, resolution, ts)
) STRICT, WITHOUT ROWID;

-- +goose Down
DROP TABLE metrics;
