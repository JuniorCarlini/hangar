-- +goose Up
-- Dependency and vulnerability monitor (docs/14). Each scan reads what runs
-- in every service container (OS packages, Python/npm/Composer packages) and
-- the image tag, asks OSV.dev and the image registry, and keeps one row per
-- finding. A finding that disappears from a later scan is resolved, not
-- deleted, so the history and "only warn about what is new" both work.
--
-- service_id is NULL for server-level targets (the Caddy edge image); target
-- then names it ("edge"). For services, target is "".
CREATE TABLE dependency_findings (
    id              TEXT    PRIMARY KEY,
    service_id      TEXT    REFERENCES services (id) ON DELETE CASCADE,
    target          TEXT    NOT NULL DEFAULT '',
    ecosystem       TEXT    NOT NULL, -- PyPI, npm, Packagist, Debian:13, Alpine:v3.22, image
    package         TEXT    NOT NULL,
    current_version TEXT    NOT NULL,
    latest_version  TEXT    NOT NULL DEFAULT '',
    fixed_version   TEXT    NOT NULL DEFAULT '',
    severity        TEXT    NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown', 'none')),
    level           TEXT    NOT NULL CHECK (level IN ('critical', 'security', 'minor', 'major')),
    advisory_id     TEXT    NOT NULL DEFAULT '', -- OSV id (GHSA-…, PYSEC-…, CVE-…); '' for tag updates
    aliases         TEXT    NOT NULL DEFAULT '', -- other ids of the same advisory, comma separated
    summary         TEXT    NOT NULL DEFAULT '',
    source          TEXT    NOT NULL DEFAULT '', -- where the version came from (file or package database)
    kind            TEXT    NOT NULL CHECK (kind IN ('vuln', 'patch', 'minor', 'major')),
    first_seen_at   INTEGER NOT NULL,
    last_seen_at    INTEGER NOT NULL,
    resolved_at     INTEGER,
    notified_at     INTEGER
) STRICT;
-- One row per (target, package, advisory, kind); a tag update has advisory ''.
CREATE UNIQUE INDEX dependency_findings_key
    ON dependency_findings (coalesce(service_id, ''), target, ecosystem, package, advisory_id, kind);
CREATE INDEX dependency_findings_open ON dependency_findings (resolved_at, level);

-- "Ignore until version X" or "ignore for N days", always with a reason
-- (the audit log keeps who and why).
CREATE TABLE finding_ignores (
    id            TEXT    PRIMARY KEY,
    service_id    TEXT    REFERENCES services (id) ON DELETE CASCADE,
    target        TEXT    NOT NULL DEFAULT '',
    package       TEXT    NOT NULL,
    advisory_id   TEXT    NOT NULL DEFAULT '', -- '' = every finding of the package
    until_version TEXT    NOT NULL DEFAULT '', -- '' = no version condition
    until_at      INTEGER,                     -- NULL = no time limit
    reason        TEXT    NOT NULL,
    created_by    TEXT,
    created_at    INTEGER NOT NULL
) STRICT;

-- Result of each target's last inventory, so the page can say what could
-- not be read (a distroless image without find/cat, for example).
CREATE TABLE dependency_scans (
    target_key TEXT    PRIMARY KEY, -- service id, or "edge"
    scanned_at INTEGER NOT NULL,
    packages   INTEGER NOT NULL,
    error      TEXT    NOT NULL DEFAULT ''
) STRICT;

-- +goose Down
DROP TABLE dependency_scans;
DROP TABLE finding_ignores;
DROP INDEX dependency_findings_open;
DROP INDEX dependency_findings_key;
DROP TABLE dependency_findings;
