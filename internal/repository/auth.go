package repository

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
)

// AuthRepository — хранилище входа: одноразовые коды, refresh-токены и
// отзыв access-токенов. Пользователи — в UserRepository.
type AuthRepository struct {
	pool *pgxpool.Pool
}

func NewAuthRepository(pool *pgxpool.Pool) *AuthRepository {
	return &AuthRepository{pool: pool}
}

// ---- одноразовые коды ----

const authCodeColumns = `id, user_id, purpose, code_hash, attempts, expires_at, consumed_at, created_at`

func scanAuthCode(row rowScanner) (*auth.AuthCode, error) {
	c := &auth.AuthCode{}
	err := row.Scan(
		&c.ID, &c.UserID, &c.Purpose, &c.CodeHash, &c.Attempts,
		&c.ExpiresAt, &c.ConsumedAt, &c.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// IssueAuthCode гасит предыдущий живой код и вставляет новый одной
// транзакцией. Двумя отдельными запросами это гонка: параллельный вызов
// успел бы вставить свой код между ними и упереться в уникальный индекс.
func (r *AuthRepository) IssueAuthCode(
	ctx context.Context,
	userID user.UserID,
	purpose auth.CodePurpose,
	codeHash string,
	expiresAt time.Time,
) (*auth.AuthCode, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`UPDATE auth_codes SET consumed_at = NOW()
		  WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
		userID, purpose,
	); err != nil {
		return nil, err
	}

	code, err := scanAuthCode(tx.QueryRow(ctx,
		`INSERT INTO auth_codes (user_id, purpose, code_hash, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+authCodeColumns,
		userID, purpose, codeHash, expiresAt,
	))
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return code, nil
}

func (r *AuthRepository) LatestAuthCode(ctx context.Context, userID user.UserID, purpose auth.CodePurpose) (*auth.AuthCode, error) {
	return scanAuthCode(r.pool.QueryRow(ctx,
		`SELECT `+authCodeColumns+` FROM auth_codes
		  WHERE user_id = $1 AND purpose = $2
		  ORDER BY created_at DESC
		  LIMIT 1`,
		userID, purpose,
	))
}

func (r *AuthRepository) IncrementAuthCodeAttempts(ctx context.Context, id string) (int, error) {
	var attempts int
	err := r.pool.QueryRow(ctx,
		`UPDATE auth_codes SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts`, id,
	).Scan(&attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, user.ErrNotFound
	}
	return attempts, err
}

func (r *AuthRepository) ConsumeAuthCode(ctx context.Context, id string) error {
	return execExpectingRow(ctx, r.pool,
		`UPDATE auth_codes SET consumed_at = NOW()
		  WHERE id = $1 AND consumed_at IS NULL`, id)
}

func (r *AuthRepository) DeleteExpiredAuthCodes(ctx context.Context) error {
	// Погашенные коды тоже не храним вечно: они нужны лишь до конца окна
	// кулдауна, а это меньше их собственного TTL.
	_, err := r.pool.Exec(ctx, `DELETE FROM auth_codes WHERE expires_at < NOW()`)
	return err
}

// ---- refresh-токены ----

func (r *AuthRepository) SaveRefreshToken(ctx context.Context, userID user.UserID, tokenHash string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt,
	)
	return err
}

func (r *AuthRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*auth.RefreshToken, error) {
	rt := &auth.RefreshToken{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, token, expires_at, revoked_at, created_at
		   FROM refresh_tokens WHERE token = $1`,
		tokenHash,
	).Scan(&rt.ID, &rt.UserID, &rt.TokenHash, &rt.ExpiresAt, &rt.RevokedAt, &rt.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	return rt, err
}

// RevokeRefreshToken помечает токен использованным. Возвращает ErrNotFound,
// если токен уже был отозван или не существует — так параллельные refresh
// с одним токеном не выдадут две пары.
func (r *AuthRepository) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return execExpectingRow(ctx, r.pool,
		`UPDATE refresh_tokens SET revoked_at = NOW()
		  WHERE token = $1 AND revoked_at IS NULL`, tokenHash)
}

func (r *AuthRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, tokenHash)
	return err
}

func (r *AuthRepository) DeleteExpiredRefreshTokens(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < NOW()`)
	return err
}

func (r *AuthRepository) DeleteAllRefreshTokens(ctx context.Context, userID user.UserID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID)
	return err
}

// ---- отзыв токенов ----

func (r *AuthRepository) TokenRevocations(ctx context.Context) (map[user.UserID]int64, error) {
	rows, err := r.pool.Query(ctx, `SELECT user_id, token_version FROM token_revocations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := map[user.UserID]int64{}
	for rows.Next() {
		var (
			id  user.UserID
			ver int64
		)
		if err := rows.Scan(&id, &ver); err != nil {
			return nil, err
		}
		versions[id] = ver
	}
	return versions, rows.Err()
}

func (r *AuthRepository) DeleteStaleTokenRevocations(ctx context.Context, before time.Time) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM token_revocations WHERE changed_at < $1`, before)
	return err
}

// ---- вход по QR-коду ----

// id заявки приходит из URL, то есть от кого угодно. Не-UUID в колонку
// типа UUID Postgres отвергает ошибкой, и без проверки мусорный id давал бы
// 500 вместо «заявки нет».
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

const qrLoginColumns = `id, secret_hash, status, user_id, requester_ip, requester_ua, expires_at, created_at`

func scanQRLogin(row rowScanner) (*auth.QRLogin, error) {
	q := &auth.QRLogin{}
	err := row.Scan(
		&q.ID, &q.SecretHash, &q.Status, &q.UserID,
		&q.RequesterIP, &q.RequesterUA, &q.ExpiresAt, &q.CreatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return q, nil
}

func (r *AuthRepository) CreateQRLogin(ctx context.Context, secretHash, ip, userAgent string, expiresAt time.Time) (*auth.QRLogin, error) {
	return scanQRLogin(r.pool.QueryRow(ctx,
		`INSERT INTO qr_logins (secret_hash, requester_ip, requester_ua, expires_at)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+qrLoginColumns,
		secretHash, ip, userAgent, expiresAt,
	))
}

func (r *AuthRepository) GetQRLogin(ctx context.Context, id string) (*auth.QRLogin, error) {
	if !uuidPattern.MatchString(id) {
		return nil, user.ErrNotFound
	}
	return scanQRLogin(r.pool.QueryRow(ctx,
		`SELECT `+qrLoginColumns+` FROM qr_logins WHERE id = $1`, id))
}

func (r *AuthRepository) GetQRLoginBySecret(ctx context.Context, secretHash string) (*auth.QRLogin, error) {
	return scanQRLogin(r.pool.QueryRow(ctx,
		`SELECT `+qrLoginColumns+` FROM qr_logins WHERE secret_hash = $1`, secretHash))
}

func (r *AuthRepository) ScanQRLogin(ctx context.Context, id string, userID user.UserID) (*auth.QRLogin, error) {
	if !uuidPattern.MatchString(id) {
		return nil, user.ErrNotFound
	}
	return scanQRLogin(r.pool.QueryRow(ctx,
		`UPDATE qr_logins SET status = 'scanned', user_id = $2
		  WHERE id = $1 AND expires_at > NOW()
		    AND (status = 'pending' OR (status = 'scanned' AND user_id = $2))
		  RETURNING `+qrLoginColumns,
		id, userID,
	))
}

func (r *AuthRepository) ApproveQRLogin(ctx context.Context, id string, userID user.UserID, completeBy time.Time) error {
	if !uuidPattern.MatchString(id) {
		return user.ErrNotFound
	}
	return execExpectingRow(ctx, r.pool,
		`UPDATE qr_logins SET status = 'approved', expires_at = GREATEST(expires_at, $3)
		  WHERE id = $1 AND user_id = $2 AND status = 'scanned' AND expires_at > NOW()`,
		id, userID, completeBy)
}

func (r *AuthRepository) RejectQRLogin(ctx context.Context, id string, userID user.UserID) error {
	if !uuidPattern.MatchString(id) {
		return user.ErrNotFound
	}
	return execExpectingRow(ctx, r.pool,
		`UPDATE qr_logins SET status = 'rejected'
		  WHERE id = $1 AND user_id = $2 AND status = 'scanned' AND expires_at > NOW()`,
		id, userID)
}

func (r *AuthRepository) ConsumeQRLogin(ctx context.Context, secretHash string) (user.UserID, error) {
	var userID user.UserID
	err := r.pool.QueryRow(ctx,
		`UPDATE qr_logins SET status = 'consumed'
		  WHERE secret_hash = $1 AND status = 'approved' AND expires_at > NOW()
		  RETURNING user_id`,
		secretHash,
	).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", user.ErrNotFound
	}
	return userID, err
}

func (r *AuthRepository) DeleteExpiredQRLogins(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM qr_logins WHERE expires_at < NOW()`)
	return err
}
