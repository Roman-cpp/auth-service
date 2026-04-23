package user

import "context"

type Service interface {
	GetByID(ctx context.Context, id UserID) (*User, error)
}
