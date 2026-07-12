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

func (s *UserService) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *UserService) DeleteUser(ctx context.Context, id user.UserID) error {
	if err := s.repo.SoftDelete(ctx, id); err != nil {
		return err
	}
	// Удалённый пользователь не должен продолжать сессию через refresh.
	return s.repo.DeleteAllRefreshTokens(ctx, id)
}
