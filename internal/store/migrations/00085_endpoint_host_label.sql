-- +goose Up
-- host_label is the first DNS label of an endpoint's automatic link
-- ("<host_label>.<ip>.sslip.io" or "<host_label>.<base_domain>"), chosen
-- once by the panel: valid for DNS, at most 55 characters and unique, so
-- two services can never share a link ("a-b"/"c" and "a"/"b-c" used to).
-- Empty until the panel fills it (new endpoints at creation, old ones at
-- startup). sslip_auto_off records that a custom domain switched the
-- automatic link off, so removing the domain turns it back on only then.
ALTER TABLE endpoints ADD COLUMN host_label TEXT NOT NULL DEFAULT '';
ALTER TABLE endpoints ADD COLUMN sslip_auto_off INTEGER NOT NULL DEFAULT 0;
CREATE UNIQUE INDEX endpoints_host_label ON endpoints (host_label) WHERE host_label != '';

-- +goose Down
DROP INDEX endpoints_host_label;
ALTER TABLE endpoints DROP COLUMN sslip_auto_off;
ALTER TABLE endpoints DROP COLUMN host_label;
