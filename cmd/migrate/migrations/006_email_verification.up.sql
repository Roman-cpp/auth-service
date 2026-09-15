ALTER TABLE users ADD COLUMN email_verified_at  TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN two_factor_enabled BOOLEAN NOT NULL DEFAULT FALSE;

-- Аккаунты, заведённые до появления подтверждения почты, считаем подтверждёнными:
-- иначе сразу после выката они все разом потеряют возможность войти.
UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL;

CREATE TABLE IF NOT EXISTS auth_codes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose     TEXT NOT NULL CHECK (purpose IN ('email_verify', 'mfa_login', 'mfa_enable')),
    -- bcrypt, а не SHA-256 как у refresh_tokens: в коде всего 6 цифр, то есть
    -- миллион вариантов — быстрый хеш при утечке таблицы перебирается мгновенно.
    code_hash   TEXT NOT NULL,
    attempts    SMALLINT NOT NULL DEFAULT 0,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Живой код на пару (пользователь, назначение) всегда ровно один: перевыпуск
-- гасит предыдущий, а гонка двух параллельных запросов упирается в индекс,
-- а не в проверку на стороне приложения.
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_codes_active
    ON auth_codes (user_id, purpose) WHERE consumed_at IS NULL;

-- Для выборки последнего кода (проверка кулдауна) и для уборки протухших.
CREATE INDEX IF NOT EXISTS idx_auth_codes_user_purpose_created
    ON auth_codes (user_id, purpose, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at ON auth_codes (expires_at);
