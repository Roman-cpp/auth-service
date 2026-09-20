-- Коды сброса удаляются до возврата старого CHECK: с ними в таблице
-- ограничение просто не добавится, и откат упадёт на полпути.
DELETE FROM auth_codes WHERE purpose = 'password_reset';

ALTER TABLE auth_codes DROP CONSTRAINT IF EXISTS auth_codes_purpose_check;

ALTER TABLE auth_codes ADD CONSTRAINT auth_codes_purpose_check
    CHECK (purpose IN ('email_verify', 'mfa_login', 'mfa_enable'));
