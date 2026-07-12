package user

import "context"

type AuthService interface {
	Register(ctx context.Context, dto CreateDTO) (*UserPreview, error)
	GetByID(ctx context.Context, id UserID) (*User, error)
}

type UserService interface {
	GetByID(ctx context.Context, id UserID) (*User, error)
	DeleteUser(ctx context.Context, id UserID) error
}
