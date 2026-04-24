package user

import "context"

type AuthService interface {
	GetByID(ctx context.Context, id UserID) (*User, error)
}

type UserService interface {
	GetAll(ctx context.Context) ([]*User, error)
	GetByID(ctx context.Context, id UserID) (*User, error)
	DeleteUser(ctx context.Context, id UserID) error
}
