package user

import (
	"context"
	"time"
)

type Repository interface {
	Create(ctx context.Context, dto CreateDTO) (*User, error)
	GetAll(ctx context.Context) ([]*User, error)
	GetByID(ctx context.Context, id UserID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	SoftDelete(ctx context.Context, id UserID) error
	SaveRefreshToken(ctx context.Context, userID UserID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	DeleteAllRefreshTokens(ctx context.Context, userID UserID) error
	DeleteExpiredRefreshTokens(ctx context.Context) error
}
