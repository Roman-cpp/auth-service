DROP TRIGGER IF EXISTS users_record_token_revocation ON users;
DROP TRIGGER IF EXISTS users_bump_token_version ON users;
DROP FUNCTION IF EXISTS users_record_token_revocation();
DROP FUNCTION IF EXISTS users_bump_token_version();
DROP TABLE IF EXISTS token_revocations;
ALTER TABLE users DROP COLUMN IF EXISTS token_version;
