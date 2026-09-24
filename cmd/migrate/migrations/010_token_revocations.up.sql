-- Версия токенов пользователя. Access-токен несёт версию, с которой выдан;
-- токен с версией ниже текущей считается отозванным. Так роль можно держать
-- в самом токене и не ходить в базу на каждый запрос, не теряя мгновенного
-- отзыва: смена роли, пароля или удаление аккаунта поднимают версию.
--
-- Версия, а не момент отзыва: iat в JWT хранится с точностью до секунды, и
-- токен, выданный в ту же секунду сразу после смены пароля, по времени был бы
-- неотличим от выданного до неё.
ALTER TABLE users ADD COLUMN token_version BIGINT NOT NULL DEFAULT 0;

-- Последние версии пользователей, у которых что-то отзывалось. auth-service
-- держит копию таблицы в памяти и сверяет с ней каждый access-токен. Строки
-- живут, пока жив хоть один токен со старой версией, — не дольше TTL
-- access-токена; дальше их убирает уборщик сервиса.
--
-- Без внешнего ключа на users: строка должна пережить физическое удаление
-- пользователя, иначе его ещё живые токены снова стали бы валидными.
CREATE TABLE token_revocations (
    user_id       UUID PRIMARY KEY,
    token_version BIGINT NOT NULL,
    changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_token_revocations_changed_at ON token_revocations (changed_at);

-- Версию поднимает база, а не приложение: так отзыв срабатывает и на ручной
-- UPDATE из консоли (например, снятие роли модератора), обойти его нельзя.
CREATE FUNCTION users_bump_token_version() RETURNS trigger AS $$
BEGIN
    -- Опустить версию нельзя: это воскресило бы отозванные токены.
    IF NEW.token_version < OLD.token_version THEN
        NEW.token_version := OLD.token_version;
    END IF;

    IF NEW.role IS DISTINCT FROM OLD.role
       OR NEW.password_hash IS DISTINCT FROM OLD.password_hash
       OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at THEN
        NEW.token_version := OLD.token_version + 1;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_bump_token_version
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION users_bump_token_version();

CREATE FUNCTION users_record_token_revocation() RETURNS trigger AS $$
DECLARE
    uid UUID;
    ver BIGINT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        uid := OLD.id;
        ver := OLD.token_version + 1;
    ELSIF NEW.token_version > OLD.token_version THEN
        uid := NEW.id;
        ver := NEW.token_version;
    ELSE
        RETURN NULL;
    END IF;

    INSERT INTO token_revocations (user_id, token_version)
    VALUES (uid, ver)
    ON CONFLICT (user_id) DO UPDATE
        SET token_version = GREATEST(token_revocations.token_version, EXCLUDED.token_version),
            changed_at    = NOW();

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_record_token_revocation
    AFTER UPDATE OR DELETE ON users
    FOR EACH ROW EXECUTE FUNCTION users_record_token_revocation();
