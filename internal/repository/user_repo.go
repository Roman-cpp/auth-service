package repository

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/domain"
)

var ErrNotFound = errors.New("record not found")
var ErrEmailTaken = errors.New("email already taken")

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// CreateUser сохраняет нового пользователя и возвращает его.
func (r *UserRepository) CreateUser(ctx context.Context, email, passwordHash string) (*domain.User, error) {
	user := &domain.User{}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash)
		 VALUES ($1, $2)
		 RETURNING id, email, password_hash, created_at`,
		email, passwordHash,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, ErrEmailTaken
		}
		return nil, err
	}
	return user, nil
}

// GetUserByEmail находит пользователя по email.
func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	user := &domain.User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE email = $1`,
		email,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return user, err
}

// GetUserByID находит пользователя по ID.
func (r *UserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user := &domain.User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, created_at FROM users WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return user, err
}

// SaveRefreshToken сохраняет refresh-токен в БД.
func (r *UserRepository) SaveRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)`,
		userID, token, expiresAt,
	)
	return err
}

// GetRefreshToken возвращает refresh-токен по значению строки.
func (r *UserRepository) GetRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	rt := &domain.RefreshToken{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, token, expires_at, created_at FROM refresh_tokens WHERE token = $1`,
		token,
	).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt, &rt.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return rt, err
}

// DeleteRefreshToken удаляет конкретный refresh-токен (logout / ротация).
func (r *UserRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE token = $1`,
		token,
	)
	return err
}

// DeleteAllUserRefreshTokens удаляет все refresh-токены пользователя.
func (r *UserRepository) DeleteAllUserRefreshTokens(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE user_id = $1`,
		userID,
	)
	return err
}

// isPgUniqueViolation проверяет, является ли ошибка нарушением уникальности PG (код 23505).
func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
