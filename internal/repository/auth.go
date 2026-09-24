package repository

import (
	"context"
	"errors"
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
