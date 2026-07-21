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

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, dto user.CreateDTO) (*user.User, error) {
	u := &user.User{}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (last_name, first_name, patronymic, email, password_hash)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, last_name, first_name, patronymic, email, password_hash, created_at`,
		dto.LastName, dto.FirstName, dto.Patronymic, dto.Email, dto.PasswordHash,
	).Scan(&u.ID, &u.LastName, &u.FirstName, &u.Patronymic, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, user.ErrEmailTaken
		}
		return nil, err
	}
	return u, nil
}

func (r *UserRepository) GetAll(ctx context.Context) ([]*user.User, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*user.User
	for rows.Next() {
		u := &user.User{}
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	u := &user.User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, last_name, first_name, patronymic, created_at
		 FROM users WHERE email = $1 AND deleted_at IS NULL`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.LastName, &u.FirstName, &u.Patronymic, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	return u, err
}

func (r *UserRepository) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	u := &user.User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, last_name, first_name, patronymic, created_at
		 FROM users WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.LastName, &u.FirstName, &u.Patronymic, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	return u, err
}

func (r *UserRepository) SoftDelete(ctx context.Context, id user.UserID) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL`,
		id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return user.ErrNotFound
	}
	return nil
}

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
		`SELECT id, user_id, token, expires_at, revoked_at, created_at FROM refresh_tokens WHERE token = $1`,
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
	tag, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = NOW() WHERE token = $1 AND revoked_at IS NULL`,
		tokenHash,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return user.ErrNotFound
	}
	return nil
}

func (r *UserRepository) DeleteRefreshToken(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE token = $1`,
		tokenHash,
	)
	return err
}

func (r *UserRepository) DeleteExpiredRefreshTokens(ctx context.Context) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE expires_at < NOW()`,
	)
	return err
}

func (r *UserRepository) DeleteAllRefreshTokens(ctx context.Context, userID user.UserID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE user_id = $1`,
		userID,
	)
	return err
}

func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
