ALTER TABLE refresh_tokens ADD COLUMN revoked_at TIMESTAMPTZ;

-- Токены теперь хранятся в виде SHA-256 хеша: старые plaintext-значения
-- больше никогда не совпадут с хешем, чистим их сразу.
DELETE FROM refresh_tokens;
