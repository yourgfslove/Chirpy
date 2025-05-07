-- name: NewRefreshForUser :exec
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    NOW() + INTERVAL '60 days'
);

-- name: GetRefreshToken :many
SELECT * FROM refresh_tokens
WHERE user_id = $1;

-- name: GetUserFromRefreshToken :one
SELECT user_id, expires_at, revoked_at FROM refresh_tokens
WHERE token = $1;

-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW()
WHERE token = $1;