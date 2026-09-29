-- Заявки на вход по QR-коду. Компьютер без сессии заводит заявку и
-- показывает её id в QR; телефон с открытой сессией сканирует и подтверждает;
-- компьютер забирает сессию, предъявив секрет из своей httpOnly-куки.
--
-- id попадает в QR и может быть увиден кем угодно (через плечо, на
-- скриншоте), поэтому сессию по нему не выдают — только по секрету.
-- В базе, как и у refresh_tokens, лишь SHA-256 от секрета: в нём 256 бит
-- энтропии, перебирать нечего.
CREATE TABLE IF NOT EXISTS qr_logins (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_hash  TEXT UNIQUE NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'scanned', 'approved', 'rejected', 'consumed')),
    -- Заполняется при сканировании: с этого момента подтвердить или отклонить
    -- заявку может только отсканировавший.
    user_id      UUID REFERENCES users(id) ON DELETE CASCADE,
    -- Кто просит вход — показывается на телефоне перед подтверждением. Без
    -- этого пользователь не отличит свой компьютер от чужого, подсунувшего
    -- ему QR (QRLjacking).
    requester_ip TEXT NOT NULL DEFAULT '',
    requester_ua TEXT NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_qr_logins_expires_at ON qr_logins (expires_at);
