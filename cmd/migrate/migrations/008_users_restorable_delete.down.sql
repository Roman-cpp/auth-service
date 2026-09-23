DROP INDEX IF EXISTS idx_users_deleted_at;
DROP INDEX IF EXISTS idx_users_email_active;

-- ВНИМАНИЕ: откат разрушителен. Глобальный UNIQUE не встанет, пока на один
-- адрес приходится больше одной строки, а после 008 их может быть сколько
-- угодно. Оставляем по одной на адрес: живую, если она есть, иначе самую
-- свежую удалённую. Остальные удалённые аккаунты теряются безвозвратно.
DELETE FROM users u
 WHERE u.id NOT IN (
    SELECT DISTINCT ON (email) id
      FROM users
     ORDER BY email, (deleted_at IS NULL) DESC, deleted_at DESC
 );

ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);
