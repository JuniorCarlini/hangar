-- name: CreateLogMark :exec
INSERT INTO log_marks (id, service_id, at, user_id, user_name) VALUES (?, ?, ?, ?, ?);

-- name: ListLogMarks :many
SELECT * FROM log_marks WHERE service_id = ? AND at >= ? ORDER BY at;
