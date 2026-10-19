-- name: CreateUser :exec
INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = ?;

-- name: CreateFirstUser :execrows
-- The first-run owner: inserted only while there is no user at all, so two
-- setup requests racing each other cannot both create an account.
INSERT INTO users (id, email, password_hash, role, created_at, updated_at)
SELECT ?, ?, ?, ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM users);

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: SetTOTPSecret :exec
UPDATE users SET totp_secret_enc = ?, totp_last_step = 0, updated_at = ? WHERE id = ?;

-- name: AdvanceTOTPStep :execrows
UPDATE users SET totp_last_step = sqlc.arg(step) WHERE id = sqlc.arg(id) AND totp_last_step < sqlc.arg(step);

-- name: RecordLoginFailure :one
-- Counts one failure in the current window; failures older than the window
-- start a new count.
UPDATE users
SET failed_logins = CASE WHEN failed_since IS NULL OR failed_since <= sqlc.arg(window_start) THEN 1 ELSE failed_logins + 1 END,
    failed_since  = CASE WHEN failed_since IS NULL OR failed_since <= sqlc.arg(window_start) THEN sqlc.arg(now) ELSE failed_since END,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
RETURNING failed_logins, lock_count, locked_until;

-- name: LockUser :execrows
-- Starts a lock unless one is already running (two failures racing past the
-- limit lock once). The failure count starts over for after the lock.
UPDATE users
SET locked_until = sqlc.arg(locked_until), lock_count = sqlc.arg(lock_count),
    failed_logins = 0, failed_since = NULL, updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND (locked_until IS NULL OR locked_until <= sqlc.arg(now));

-- name: ResetLoginFailures :exec
UPDATE users SET failed_logins = 0, failed_since = NULL, lock_count = 0 WHERE id = ?;

-- name: UnlockUser :execrows
UPDATE users SET failed_logins = 0, failed_since = NULL, lock_count = 0, locked_until = NULL, updated_at = ? WHERE email = ?;

-- name: SetPassword :exec
UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?;

-- name: InsertRecoveryCode :exec
INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?);

-- name: DeleteRecoveryCodes :exec
DELETE FROM recovery_codes WHERE user_id = ?;

-- name: UseRecoveryCode :execrows
UPDATE recovery_codes SET used_at = ?
WHERE user_id = ? AND code_hash = ? AND used_at IS NULL;

-- name: CountUnusedRecoveryCodes :one
SELECT count(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL;

-- name: CreateSession :exec
INSERT INTO sessions (id_hash, user_id, stage, csrf_token, ip, user_agent, created_at, last_seen_at, expires_at, sudo_until)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSession :one
SELECT s.id_hash, s.user_id, s.stage, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at, s.sudo_until,
       u.role, u.locked_until, u.locale, u.theme, u.email, u.name, u.all_projects,
       CAST(coalesce(length(u.totp_secret_enc), 0) > 0 AS INTEGER) AS has_totp
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.id_hash = ?;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?;

-- name: SetUserLastSeen :exec
UPDATE users SET last_seen_at = sqlc.arg(at) WHERE id = sqlc.arg(id) AND last_seen_at < sqlc.arg(at);

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id_hash = ?;

-- name: DeleteUserSessions :exec
DELETE FROM sessions WHERE user_id = ?;

-- name: DeleteExpiredSessions :execrows
DELETE FROM sessions WHERE expires_at < sqlc.arg(now) OR last_seen_at < sqlc.arg(idle_before);

-- name: SetPreferences :exec
UPDATE users SET locale = ?, theme = ?, updated_at = ? WHERE id = ?;

-- name: ClearTOTP :exec
UPDATE users SET totp_secret_enc = NULL, totp_last_step = 0, updated_at = ? WHERE id = ?;

-- name: DeleteOtherSessions :exec
DELETE FROM sessions WHERE user_id = ? AND id_hash != ?;

-- name: SetUserName :exec
UPDATE users SET name = ?, updated_at = ? WHERE id = ?;

-- name: ListUserSessions :many
SELECT id_hash, ip, user_agent, created_at, last_seen_at FROM sessions
WHERE user_id = ? AND stage = 'active' AND expires_at > ? ORDER BY last_seen_at DESC;

-- name: DeleteUserSession :execrows
DELETE FROM sessions WHERE user_id = ? AND id_hash = ?;

-- name: ListUsers :many
SELECT u.id, u.email, u.name, u.role, u.all_projects, u.locked_until, u.created_at,
       CAST(coalesce(length(u.totp_secret_enc), 0) > 0 AS INTEGER) AS has_totp,
       CAST(max(u.last_seen_at, coalesce((SELECT max(s.last_seen_at) FROM sessions s WHERE s.user_id = u.id AND s.stage = 'active'), 0)) AS INTEGER) AS last_seen_at
FROM users u
ORDER BY CASE u.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'operator' THEN 2 ELSE 3 END, u.email;

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: CountOwners :one
SELECT count(*) FROM users WHERE role = 'owner';

-- name: SetUserAccess :exec
UPDATE users SET role = ?, all_projects = ?, updated_at = ? WHERE id = ?;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = ?;

-- name: UserProjectSlugs :many
SELECT p.slug FROM user_projects up JOIN projects p ON p.id = up.project_id
WHERE up.user_id = ? ORDER BY p.slug;

-- name: AllUserProjects :many
SELECT up.user_id, p.slug FROM user_projects up JOIN projects p ON p.id = up.project_id
ORDER BY p.slug;

-- name: ClearUserProjects :exec
DELETE FROM user_projects WHERE user_id = ?;

-- name: AddUserProject :exec
INSERT INTO user_projects (user_id, project_id)
SELECT ?, id FROM projects WHERE slug = ?;

-- name: CreateInvite :exec
INSERT INTO invites (id, token_hash, email, role, all_projects, projects_json, created_by, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ListOpenInvites :many
SELECT * FROM invites WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC;

-- name: GetInviteByToken :one
SELECT * FROM invites WHERE token_hash = ?;

-- name: UseInvite :execrows
UPDATE invites SET used_at = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?;

-- name: DeleteInvite :execrows
DELETE FROM invites WHERE id = ? AND used_at IS NULL;

-- name: DeleteOpenInvitesForEmail :execrows
DELETE FROM invites WHERE lower(email) = lower(?) AND used_at IS NULL;
