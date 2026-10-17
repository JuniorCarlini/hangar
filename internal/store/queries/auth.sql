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
UPDATE users
SET failed_logins = failed_logins + 1,
    locked_at = CASE WHEN failed_logins + 1 >= sqlc.arg(lock_after) THEN sqlc.arg(now) ELSE locked_at END,
    updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id)
RETURNING failed_logins, locked_at;

-- name: ResetLoginFailures :exec
UPDATE users SET failed_logins = 0 WHERE id = ?;

-- name: UnlockUser :execrows
UPDATE users SET failed_logins = 0, locked_at = NULL, updated_at = ? WHERE email = ?;

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
       u.role, u.locked_at, u.locale, u.theme, u.email, u.name,
       CAST(coalesce(length(u.totp_secret_enc), 0) > 0 AS INTEGER) AS has_totp
FROM sessions s JOIN users u ON u.id = s.user_id
WHERE s.id_hash = ?;

-- name: TouchSession :exec
UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?;

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
