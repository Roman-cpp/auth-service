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

func (r *UserRepository) Create(ctx context.Context, email, passwordHash string) (*user.User, error) {
	u := &user.User{}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash)
		 VALUES ($1, $2)
		 RETURNING id, email, password_hash, created_at`,
		email, passwordHash,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
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
		`SELECT id, email, password_hash, created_at FROM users WHERE email = $1 AND deleted_at IS NULL`,
		email,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	return u, err
}

func (r *UserRepository) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	u := &user.User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
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

func (r *UserRepository) SaveRefreshToken(ctx context.Context, userID user.UserID, token string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, token, expiresAt,
	)
	return err
}

func (r *UserRepository) GetRefreshToken(ctx context.Context, token string) (*user.RefreshToken, error) {
	rt := &user.RefreshToken{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, token, expires_at, created_at FROM refresh_tokens WHERE token = $1`,
		token,
	).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	return rt, err
}

func (r *UserRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE token = $1`,
		token,
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
