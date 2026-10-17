-- +goose Up
-- Where the card sits on the project canvas (moved by dragging); NULL =
-- automatic layout.
ALTER TABLE services ADD COLUMN canvas_x INTEGER;
ALTER TABLE services ADD COLUMN canvas_y INTEGER;

-- +goose Down
ALTER TABLE services DROP COLUMN canvas_y;
ALTER TABLE services DROP COLUMN canvas_x;
