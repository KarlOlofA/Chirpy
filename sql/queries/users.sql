-- name: CreateUser :one
INSERT INTO users(id, created_at, updated_at, email, hashed_password)
VALUES(
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByUUID :one
SELECT * FROM users WHERE id = $1;

-- name: UpdateUserPassword :exec
UPDATE users
SET hashed_password = $1
WHERE email = $2;

-- name: ResetUsers :exec
TRUNCATE TABLE users CASCADE;