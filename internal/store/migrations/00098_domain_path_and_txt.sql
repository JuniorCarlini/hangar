-- +goose Up
-- How each certificate request reached the server (docs/28): "direct" (the
-- name resolves here) or "cloudflare" (proxied by Cloudflare, orange cloud);
-- empty for rows written before this column existed.
ALTER TABLE tls_ask_log ADD COLUMN via TEXT NOT NULL DEFAULT '';
-- A service taking customer domains may also require the ownership TXT
-- record (_hangar.<domain>), so nobody can attach a domain that is not
-- theirs even if the app says yes.
ALTER TABLE services ADD COLUMN domain_require_txt INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE services DROP COLUMN domain_require_txt;
ALTER TABLE tls_ask_log DROP COLUMN via;
