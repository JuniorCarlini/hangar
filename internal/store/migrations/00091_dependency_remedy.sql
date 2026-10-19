-- +goose Up
-- What fixes each vulnerability (docs/14), decided by the scan: a deploy (the
-- registry has a newer build of the same tag that carries the fix), another
-- tag (remedy_tag names it), the app's own code (services built from Git),
-- the edge (comes with a Hangar release), or nothing yet (no fixed version,
-- or no image carries it). '' on tag updates and on rows from before.
ALTER TABLE dependency_findings ADD COLUMN remedy TEXT NOT NULL DEFAULT '';
ALTER TABLE dependency_findings ADD COLUMN remedy_tag TEXT NOT NULL DEFAULT '';

-- Packages of images the panel pulled only to look inside them (a newer
-- build of a tag, a newer tag), by digest: an image with a given digest
-- never changes, so each is pulled and read at most once. A failure is kept
-- too, and tried again after a while.
CREATE TABLE image_probes (
    digest        TEXT    PRIMARY KEY, -- sha256:…
    packages_json TEXT    NOT NULL DEFAULT '[]',
    error         TEXT    NOT NULL DEFAULT '',
    probed_at     INTEGER NOT NULL
) STRICT;

-- +goose Down
DROP TABLE image_probes;
ALTER TABLE dependency_findings DROP COLUMN remedy_tag;
ALTER TABLE dependency_findings DROP COLUMN remedy;
