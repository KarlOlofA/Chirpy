-- name: CreatePost :one
INSERT INTO posts (id, created_at, updated_at, body, user_id)
VALUES(
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetAllPosts :many
SELECT * FROM posts ORDER BY created_at ASC;

-- name: GetPostFromUserId :many
SELECT * FROM posts WHERE user_id = $1 ORDER BY created_at ASC;

-- name: GetPost :one
SELECT * FROM posts WHERE id = $1;

-- name: DeletePost :exec
DELETE FROM posts WHERE id = $1;

-- name: ResetPosts :exec
TRUNCATE TABLE posts;