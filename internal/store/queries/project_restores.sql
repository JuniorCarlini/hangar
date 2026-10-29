-- name: CreateProjectRestore :exec
INSERT INTO project_restores (id, project_id, source, file_name, status, step, created_by, started_at)
VALUES (?, ?, ?, ?, 'running', ?, ?, ?);

-- name: SetProjectRestoreStep :exec
UPDATE project_restores SET step = ? WHERE id = ?;

-- name: SetProjectRestoreNotes :exec
UPDATE project_restores SET notes_json = ? WHERE id = ?;

-- name: FinishProjectRestore :exec
UPDATE project_restores SET status = ?, error = ?, finished_at = ? WHERE id = ?;

-- name: LatestProjectRestore :one
SELECT * FROM project_restores WHERE project_id = ? ORDER BY started_at DESC, rowid DESC LIMIT 1;

-- name: GetProjectRestore :one
SELECT * FROM project_restores WHERE id = ?;

-- name: FailRunningProjectRestores :exec
UPDATE project_restores SET status = 'failed', error = ?, finished_at = ? WHERE status = 'running';
