
-- name: GetPasswordHash :one
SELECT * FROM user_password_hashes 
WHERE username = $1 LIMIT 1;

-- name: SetPasswordHash :one
INSERT INTO user_password_hashes (username, password_hash)
VALUES ($1, $2)
RETURNING *;