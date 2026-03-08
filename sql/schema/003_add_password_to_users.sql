-- +goose up
ALTER TABLE users
ADD COLUMN hashed_password TEXT DEFAULT 'unset' NOT NULL;

-- +goose down
ALTER TABLE users
DROP COLUMN hashed_password;