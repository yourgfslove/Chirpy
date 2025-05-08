-- name: CreateChirp :one
WITH inserted_chirp AS (
    INSERT INTO chirps (id, created_at, updated_at, body, user_id)
    VALUES (
        gen_random_uuid(),
            NOW(),
            NOW(),
            $1,
            $2
    )
    RETURNING *
)
SELECT
    inserted_chirp.id,
    inserted_chirp.created_at,
    inserted_chirp.updated_at,
    inserted_chirp.body,
    users.email AS email
FROM inserted_chirp
INNER JOIN users ON users.id = inserted_chirp.user_id;

-- name: GetAllChirps :many
SELECT * FROM chirps
ORDER BY created_at ASC;


-- name: GetOneChirp :one
SELECT * FROM chirps
WHERE id=$1;

-- name: ChirpDeleteByID :exec
DELETE FROM chirps
WHERE id = $1;

-- name: GetChirpsByUserID :many
SELECT * FROM chirps
WHERE user_id = $1
ORDER BY created_at;