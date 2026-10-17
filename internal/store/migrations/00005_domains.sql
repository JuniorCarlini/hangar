-- +goose Up
-- Fixed domains routed to a service (docs/03).
CREATE TABLE domains (
    id         TEXT    PRIMARY KEY,
    service_id TEXT    NOT NULL REFERENCES services (id) ON DELETE CASCADE,
    hostname   TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX domains_service ON domains (service_id);

-- A service may accept dynamic (customer) domains: certificates are issued on
-- demand only after the app itself authorizes each hostname. At most one
-- service per server (enforced by the partial unique index).
ALTER TABLE services ADD COLUMN dynamic_domains INTEGER NOT NULL DEFAULT 0;
ALTER TABLE services ADD COLUMN domain_check_path TEXT NOT NULL DEFAULT '/.well-known/hangar/domain-check';
-- HMAC secret shared with the app; encrypted (services|<id>|domain_check_secret).
ALTER TABLE services ADD COLUMN domain_check_secret_enc BLOB;
CREATE UNIQUE INDEX services_single_dynamic ON services (dynamic_domains) WHERE dynamic_domains = 1;

CREATE TABLE domain_blocklist (
    hostname   TEXT    PRIMARY KEY,
    reason     TEXT    NOT NULL,
    created_by TEXT,
    created_at INTEGER NOT NULL
) STRICT;

-- Aggregated decisions of the TLS "ask" endpoint: one row per
-- (hostname, decision, hour) with a counter, so an attack with thousands of
-- attempts stays small (docs/20).
CREATE TABLE tls_ask_log (
    hostname TEXT    NOT NULL,
    decision TEXT    NOT NULL CHECK (decision IN ('allow', 'deny')),
    reason   TEXT    NOT NULL,
    hour     INTEGER NOT NULL,
    count    INTEGER NOT NULL DEFAULT 1,
    last_at  INTEGER NOT NULL,
    PRIMARY KEY (hostname, decision, hour)
) STRICT, WITHOUT ROWID;
CREATE INDEX tls_ask_log_hour ON tls_ask_log (hour);

-- +goose Down
DROP TABLE tls_ask_log;
DROP TABLE domain_blocklist;
DROP INDEX services_single_dynamic;
ALTER TABLE services DROP COLUMN domain_check_secret_enc;
ALTER TABLE services DROP COLUMN domain_check_path;
ALTER TABLE services DROP COLUMN dynamic_domains;
DROP TABLE domains;
