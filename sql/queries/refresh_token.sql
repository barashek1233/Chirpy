-- name: CreateToken :one
INSERT INTO refresh_token (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    $4
)
RETURNING *;
--

-- name: GetRefreshToken :one
SELECT * FROM refresh_token WHERE token = $1;
--

-- name: RevokerefreshToken :exec
UPDATE refresh_token
SET updated_at = NOW(), revoked_at = NOW()
WHERE token = $1;
--