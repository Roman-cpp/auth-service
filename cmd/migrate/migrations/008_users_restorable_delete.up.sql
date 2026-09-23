-- Уникальность email теперь считается только среди живых аккаунтов.
--
-- Глобальный UNIQUE держал адрес занятым и после удаления: повторная
-- регистрация упиралась в него навсегда, а GetByEmail при этом отвечал
-- «нет такого пользователя». Частичный индекс освобождает адрес сразу,
-- а конфликт восстановления с новым владельцем ловится тем же индексом —
-- в БД, а не проверкой в приложении.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_active
    ON users (email) WHERE deleted_at IS NULL;

-- Удалённых строк с одним адресом может накопиться несколько (удалил →
-- зарегистрировался заново → удалил), поэтому выборка восстановимого
-- аккаунта идёт по deleted_at DESC. Этот же индекс обслуживает уборку
-- просроченных.
CREATE INDEX IF NOT EXISTS idx_users_deleted_at
    ON users (email, deleted_at DESC) WHERE deleted_at IS NOT NULL;
