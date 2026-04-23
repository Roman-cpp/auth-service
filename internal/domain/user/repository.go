package user

import (
	"context"
	"time"
)

type Repository interface {
	Create(ctx context.Context, email, passwordHash string) (*User, error)
	GetByID(ctx context.Context, id UserID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	SaveRefreshToken(ctx context.Context, userID UserID, token string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllRefreshTokens(ctx context.Context, userID UserID) error
}
