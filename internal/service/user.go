package service

import (
	"context"

	"github.com/krypton/auth-service/internal/domain/user"
)

type UserService struct {
	repo user.Repository
}

func NewUserService(repo user.Repository) *UserService {
	return &UserService{repo: repo}
}

func (s *UserService) GetAll(ctx context.Context) ([]*user.User, error) {
	return s.repo.GetAll(ctx)
}

func (s *UserService) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *UserService) DeleteUser(ctx context.Context, id user.UserID) error {
	return s.repo.SoftDelete(ctx, id)
}
