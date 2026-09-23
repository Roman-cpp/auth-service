-- Сброс пароля — четвёртое назначение одноразового кода. Список значений
-- зашит в CHECK из 006, поэтому ограничение приходится пересобирать: иначе
-- INSERT с 'password_reset' упрётся в него уже на первой заявке.
ALTER TABLE auth_codes DROP CONSTRAINT IF EXISTS auth_codes_purpose_check;

ALTER TABLE auth_codes ADD CONSTRAINT auth_codes_purpose_check
    CHECK (purpose IN ('email_verify', 'mfa_login', 'mfa_enable', 'password_reset'));
