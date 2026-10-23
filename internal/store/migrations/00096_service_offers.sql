-- +goose Up
-- Variables a service offers to the others (docs/08 "Conectar serviços"):
-- a template declares what it offers ([[exports]]); a service made by hand
-- (an image, a Git repository) offers the variables marked here. Only
-- offered values show up when connecting, so a service that offers nothing
-- cannot be connected to. The row goes with the variable.
CREATE TABLE service_offers (
    service_id TEXT NOT NULL,
    key        TEXT NOT NULL,
    PRIMARY KEY (service_id, key),
    FOREIGN KEY (service_id, key) REFERENCES env_vars (service_id, key) ON DELETE CASCADE
) STRICT;

-- +goose Down
DROP TABLE service_offers;
