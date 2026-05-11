-- name: GetUser :one
SELECT * FROM "user"
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM "user"
WHERE email = $1;

-- name: CreateUser :one
INSERT INTO "user" (name, email, avatar_url)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateUser :one
UPDATE "user" SET
    name = COALESCE($2, name),
    avatar_url = COALESCE($3, avatar_url),
    language = COALESCE($4, language),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: MarkUserOnboarded :one
UPDATE "user" SET
    onboarded_at = COALESCE(onboarded_at, now()),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: PatchUserOnboarding :one
UPDATE "user" SET
    onboarding_questionnaire = COALESCE(sqlc.narg('questionnaire'), onboarding_questionnaire),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: JoinCloudWaitlist :one
-- Records interest in cloud runtimes. Does NOT mark onboarding
-- complete — the user still has to pick a real path (CLI / Skip)
-- in Step 3. Repeating the call overwrites email + reason.
UPDATE "user" SET
    cloud_waitlist_email = $2,
    cloud_waitlist_reason = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: SetStarterContentState :one
-- Atomically transition starter_content_state. The handler is
-- responsible for checking the current value first (to decide between
-- "transition NULL -> imported and run the seeding" vs "already
-- decided, short-circuit"). Using COALESCE here would swallow the
-- transition, so this is a straight assignment.
UPDATE "user" SET
    starter_content_state = $2,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetUserTokenVersion :one
-- Returns the current token_version for a user. The Auth middleware
-- compares the JWT's `tv` claim against this to invalidate tokens
-- minted before the most recent revocation event (logout-all, password
-- change, admin force-revoke). Returns 0 if the user does not exist —
-- the caller still has to reject the request in that case via the
-- normal GetUser lookup; this query is only used after that succeeds.
SELECT token_version FROM "user"
WHERE id = $1;

-- name: BumpUserTokenVersion :one
-- Increments token_version, invalidating every JWT minted for this
-- user before the bump. The Logout / kick-session paths call this.
-- Uses a returning so the caller can see the new value (useful for
-- tests and for stamping the cache).
UPDATE "user" SET
    token_version = token_version + 1,
    updated_at = now()
WHERE id = $1
RETURNING token_version;
