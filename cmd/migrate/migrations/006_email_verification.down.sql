DROP TABLE IF EXISTS auth_codes;

ALTER TABLE users DROP COLUMN IF EXISTS two_factor_enabled;
ALTER TABLE users DROP COLUMN IF EXISTS email_verified_at;
