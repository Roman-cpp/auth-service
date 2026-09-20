package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/domain/user"
)

// Набор колонок пользователя перечислен один раз: раньше три запроса
// дублировали список руками, и каждое новое поле приходилось дописывать
// в три места.
const userColumns = `id, email, password_hash, last_name, first_name, patronymic,
	email_verified_at, two_factor_enabled, created_at, updated_at`

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*user.User, error) {
	u := &user.User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.LastName, &u.FirstName, &u.Patronymic,
		&u.EmailVerifiedAt, &u.TwoFactorEnabled, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Upsert: повторная регистрация на ещё не подтверждённый адрес перезаписывает
// заявку вместо 409. Иначе любой мог бы занять чужой email навсегда — просто
// начав регистрацию и не подтвердив её. Подтверждённый аккаунт защищён
// условием в DO UPDATE: конфликт по нему не даёт ни одной строки, что и
// означает ErrEmailTaken.
func (r *UserRepository) Upsert(ctx context.Context, dto user.CreateDTO) (*user.User, error) {
	u, err := scanUser(r.pool.QueryRow(ctx,
		`INSERT INTO users (last_name, first_name, patronymic, email, password_hash)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (email) DO UPDATE
		    SET last_name     = EXCLUDED.last_name,
		        first_name    = EXCLUDED.first_name,
		        patronymic    = EXCLUDED.patronymic,
		        password_hash = EXCLUDED.password_hash,
		        updated_at    = NOW()
		  WHERE users.email_verified_at IS NULL AND users.deleted_at IS NULL
		 RETURNING `+userColumns,
		dto.LastName, dto.FirstName, dto.Patronymic, dto.Email, dto.PasswordHash,
	))
	if errors.Is(err, user.ErrNotFound) || isPgUniqueViolation(err) {
		return nil, user.ErrEmailTaken
	}
	return u, err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1 AND deleted_at IS NULL`,
		email,
	))
}

func (r *UserRepository) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1 AND deleted_at IS NULL`,
		id,
	))
}

func (r *UserRepository) SoftDelete(ctx context.Context, id user.UserID) error {
	return r.execExpectingRow(ctx,
		`UPDATE users SET deleted_at = NOW(), updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL`, id)
}

func (r *UserRepository) MarkEmailVerified(ctx context.Context, id user.UserID) error {
	return r.execExpectingRow(ctx,
		`UPDATE users SET email_verified_at = NOW(), updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL AND email_verified_at IS NULL`, id)
}

// UpdatePassword не проверяет email_verified_at: сброс пароля доступен
// только подтверждённому аккаунту, но решается это в сервисе — здесь важно
// лишь не воскресить удалённого пользователя.
func (r *UserRepository) UpdatePassword(ctx context.Context, id user.UserID, passwordHash string) error {
	return r.execExpectingRow(ctx,
		`UPDATE users SET password_hash = $2, updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL`, id, passwordHash)
}

func (r *UserRepository) SetTwoFactorEnabled(ctx context.Context, id user.UserID, enabled bool) error {
	return r.execExpectingRow(ctx,
		`UPDATE users SET two_factor_enabled = $2, updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL AND two_factor_enabled <> $2`, id, enabled)
}

// ---- одноразовые коды ----

const authCodeColumns = `id, user_id, purpose, code_hash, attempts, expires_at, consumed_at, created_at`

func scanAuthCode(row rowScanner) (*user.AuthCode, error) {
	c := &user.AuthCode{}
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
func (r *UserRepository) IssueAuthCode(
	ctx context.Context,
	userID user.UserID,
	purpose user.CodePurpose,
	codeHash string,
	expiresAt time.Time,
) (*user.AuthCode, error) {
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

func (r *UserRepository) LatestAuthCode(ctx context.Context, userID user.UserID, purpose user.CodePurpose) (*user.AuthCode, error) {
	return scanAuthCode(r.pool.QueryRow(ctx,
		`SELECT `+authCodeColumns+` FROM auth_codes
		  WHERE user_id = $1 AND purpose = $2
		  ORDER BY created_at DESC
		  LIMIT 1`,
		userID, purpose,
	))
}

func (r *UserRepository) IncrementAuthCodeAttempts(ctx context.Context, id string) (int, error) {
	var attempts int
	err := r.pool.QueryRow(ctx,
		`UPDATE auth_codes SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts`, id,
	).Scan(&attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, user.ErrNotFound
	}
	return attempts, err
}

func (r *UserRepository) ConsumeAuthCode(ctx context.Context, id string) error {
	return r.execExpectingRow(ctx,
		`UPDATE auth_codes SET consumed_at = NOW()
		  WHERE id = $1 AND consumed_at IS NULL`, id)
}

func (r *UserRepository) DeleteExpiredAuthCodes(ctx context.Context) error {
	// Погашенные коды тоже не храним вечно: они нужны лишь до конца окна
	// кулдауна, а это меньше их собственного TTL.
	_, err := r.pool.Exec(ctx, `DELETE FROM auth_codes WHERE expires_at < NOW()`)
	return err
}

// ---- refresh-токены ----

func (r *UserRepository) SaveRefreshToken(ctx context.Context, userID user.UserID, tokenHash string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt,
	)
	return err
}

func (r *UserRepository) GetRefreshToken(ctx context.Context, tokenHash string) (*user.RefreshToken, error) {
	rt := &user.RefreshToken{}
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
func (r *UserRepository) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return r.execExpectingRow(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW()
		  WHERE token = $1 AND revoked_at IS NULL`, tokenHash)
}

func (r *UserRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, tokenHash)
	return err
}

func (r *UserRepository) DeleteExpiredRefreshTokens(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE expires_at < NOW()`)
	return err
}

func (r *UserRepository) DeleteAllRefreshTokens(ctx context.Context, userID user.UserID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID)
	return err
}

// ---- helpers ----

// execExpectingRow превращает «запрос не задел ни одной строки» в ErrNotFound.
// Все UPDATE выше несут в WHERE ещё и условие состояния (не удалён, не
// погашен, не отозван), поэтому ноль строк — это и «нет записи», и «состояние
// уже изменил кто-то другой»; для вызывающего это одно и то же.
func (r *UserRepository) execExpectingRow(ctx context.Context, sql string, args ...any) error {
	tag, err := r.pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return user.ErrNotFound
	}
	return nil
}

func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
