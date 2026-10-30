-- +goose Up
-- Hostnames approved for a certificate, one row each, kept apart from
-- tls_ask_log (docs/03, docs/20). The hourly cap on new certificates and
-- the renewal exemption read this table, so they no longer depend on the
-- ask log: that log has a row ceiling anyone on the internet can fill,
-- and a full log used to switch the cap off. Only approvals land here and
-- approvals are themselves capped, so the table cannot be flooded.
CREATE TABLE tls_approvals (
    hostname   TEXT    PRIMARY KEY,
    first_hour INTEGER NOT NULL,
    last_hour  INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
CREATE INDEX tls_approvals_first_hour ON tls_approvals (first_hour);

INSERT INTO tls_approvals (hostname, first_hour, last_hour)
SELECT hostname, min(hour), max(hour) FROM tls_ask_log WHERE decision = 'allow' GROUP BY hostname;

-- +goose Down
DROP TABLE tls_approvals;
