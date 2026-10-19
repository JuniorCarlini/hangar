-- +goose Up
-- A named volume shared by several services of one template or compose
-- import (docs/08): it belongs to one of them (the owner) and the others
-- mount the owner's Docker volume. owner_service_id is NULL on the owner's
-- own row and on every volume from before; on a sharer's row it names the
-- owner. The reference keeps the owner from being deleted while another
-- service still mounts its volume (the panel says so first).
ALTER TABLE service_volumes ADD COLUMN owner_service_id TEXT REFERENCES services (id);

CREATE INDEX service_volumes_owner ON service_volumes (owner_service_id) WHERE owner_service_id IS NOT NULL;

-- +goose Down
DROP INDEX service_volumes_owner;
ALTER TABLE service_volumes DROP COLUMN owner_service_id;
