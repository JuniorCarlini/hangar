-- +goose Up
-- Alerts and notifications (docs/06, docs/17 § 3.10). Rules apply to the
-- whole server; each channel picks the lowest severity it receives (security
-- alerts go to every enabled channel regardless).

-- Where alerts are sent. Everything about the channel (bot token, SMTP
-- password, webhook URL and secret) lives in config_enc, encrypted with the
-- master key (associated data = alert_channels|<id>|config_enc). target is a
-- short, non-secret summary for the list ("chat 12345", "ops@example.com",
-- "n8n.example.com").
CREATE TABLE alert_channels (
    id           TEXT    PRIMARY KEY,
    kind         TEXT    NOT NULL CHECK (kind IN ('telegram', 'email', 'webhook')),
    name         TEXT    NOT NULL,
    target       TEXT    NOT NULL,
    min_severity TEXT    NOT NULL DEFAULT 'warning' CHECK (min_severity IN ('info', 'warning', 'critical')),
    enabled      INTEGER NOT NULL DEFAULT 1,
    config_enc   BLOB    NOT NULL,
    created_by   TEXT,
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
) STRICT;

-- Server rules the operator can tune. A missing row means the default.
-- Security alerts have no row: they cannot be turned off.
CREATE TABLE alert_rules (
    kind       TEXT    PRIMARY KEY,
    enabled    INTEGER NOT NULL,
    threshold  INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

-- Every alert raised, delivered or not (the bell and the history). The text
-- is rendered from kind + params in the reader's language. dedup_key groups
-- the alerts of one condition ("container_down|svc_x"); repeats counts the
-- duplicates that were swallowed instead of being sent again.
CREATE TABLE alerts (
    id          INTEGER PRIMARY KEY,
    kind        TEXT    NOT NULL,
    severity    TEXT    NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    category    TEXT    NOT NULL CHECK (category IN ('server', 'security')),
    dedup_key   TEXT    NOT NULL,
    params_json TEXT    NOT NULL DEFAULT '{}',
    resolved    INTEGER NOT NULL DEFAULT 0,
    muted       INTEGER NOT NULL DEFAULT 0,
    repeats     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    last_at     INTEGER NOT NULL
) STRICT;
CREATE INDEX alerts_dedup ON alerts (dedup_key, id);
CREATE INDEX alerts_created ON alerts (created_at);

-- One row per alert per channel (or per test send): what happened when
-- Hangar tried to deliver it. error never holds secrets (URLs with tokens
-- are stripped before it is written).
CREATE TABLE alert_deliveries (
    id           INTEGER PRIMARY KEY,
    alert_id     INTEGER REFERENCES alerts (id) ON DELETE CASCADE,
    channel_id   TEXT    REFERENCES alert_channels (id) ON DELETE SET NULL,
    channel_name TEXT    NOT NULL,
    channel_kind TEXT    NOT NULL,
    kind         TEXT    NOT NULL,
    status       TEXT    NOT NULL CHECK (status IN ('sent', 'failed', 'dropped')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    error        TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL
) STRICT;
CREATE INDEX alert_deliveries_created ON alert_deliveries (created_at);

-- The newest alert each user has seen (the unread dot on the bell).
CREATE TABLE alert_seen (
    user_id TEXT    PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    last_id INTEGER NOT NULL
) STRICT;

-- Addresses each user has logged in from: a login from an address not in
-- here raises "login from a new IP".
CREATE TABLE login_ips (
    user_id  TEXT    NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    ip       TEXT    NOT NULL,
    first_at INTEGER NOT NULL,
    last_at  INTEGER NOT NULL,
    PRIMARY KEY (user_id, ip)
) STRICT, WITHOUT ROWID;

-- Addresses already used before this version are known: updating must not
-- raise a "new IP" alert for every user's next login.
INSERT OR IGNORE INTO login_ips (user_id, ip, first_at, last_at)
SELECT a.actor_id, a.ip,
       CAST(strftime('%s', MIN(a.ts)) AS INTEGER), CAST(strftime('%s', MAX(a.ts)) AS INTEGER)
FROM audit_log a
JOIN users u ON u.id = a.actor_id
WHERE a.action = 'auth.login.ok' AND a.outcome = 'ok' AND a.ip IS NOT NULL
GROUP BY a.actor_id, a.ip;

-- +goose Down
DROP TABLE login_ips;
DROP TABLE alert_seen;
DROP TABLE alert_deliveries;
DROP TABLE alerts;
DROP TABLE alert_rules;
DROP TABLE alert_channels;
