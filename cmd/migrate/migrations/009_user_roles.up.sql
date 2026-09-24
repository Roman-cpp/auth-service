-- Роль пользователя. Их две: обычный пользователь и модератор — модератор
-- ведёт админку (список пользователей, заведение аккаунтов). Отдельной роли
-- admin нет намеренно: пока все права админки у одной роли.
ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
    CHECK (role IN ('user', 'moderator'));

-- Аккаунт, заведённый модератором, получает временный пароль, и войти с ним
-- нельзя, пока владелец не сменит его на свой: временный пароль видел
-- модератор, а значит, он не секрет владельца.
ALTER TABLE users ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- Кто завёл аккаунт. NULL — зарегистрировался сам. SET NULL, а не каскад:
-- уход модератора не должен уносить заведённых им пользователей.
ALTER TABLE users ADD COLUMN created_by UUID REFERENCES users(id) ON DELETE SET NULL;
