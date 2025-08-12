-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;
--

-- name: DeletAllUsers :exec
DELETE FROM users;
--

-- name: AddPassWordForEmail :exec
UPDATE users
SET hashed_password = $1
WHERE email = $2;
--

-- name: GetHashPassword :one
SELECT hashed_password
FROM users
WHERE email = $1;
--

-- name: GetUserForEmail :one
SELECT *
FROM users
WHERE email = $1;
--

-- name: UserUpdatePasswd :exec
UPDATE users
SET hashed_password = $2
WHERE id = $1;
--

-- name: UserUpdateEmail :exec
UPDATE users
SET email = $2
WHERE id = $1;
--

-- name: GetUserForID :one
SELECT *
FROM users
WHERE id = $1;
--

-- name: UpdgradeToRed :exec
UPDATE users
SET is_chirpy_red = TRUE
WHERE id = $1;
--