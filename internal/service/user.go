package service

import (
	"context"
	"log/slog"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
)

type UserService struct {
	repo        user.Repository
	revocations RevocationSyncer
	cfg         config.AccountConfig
}

func NewUserService(repo user.Repository, revocations RevocationSyncer, cfg config.AccountConfig) *UserService {
	return &UserService{repo: repo, revocations: revocations, cfg: cfg}
}

func (s *UserService) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return s.repo.GetByID(ctx, id)
}

// DeleteUser помечает аккаунт удалённым и возвращает момент, до которого его
// ещё можно вернуть. Физически строка живёт до конца этого окна: её уносит
// уборщик, он же освобождает адрес окончательно.
//
// Адрес, впрочем, освобождается сразу: уникальность email считается только
// среди живых аккаунтов. Пока на него никто не зарегистрировался, удалённый
// аккаунт восстановим; как только зарегистрировался — нет.
func (s *UserService) DeleteUser(ctx context.Context, id user.UserID) (time.Time, error) {
	deletedAt, err := s.repo.SoftDelete(ctx, id)
	if err != nil {
		return time.Time{}, err
	}

	// Удалённый пользователь не должен продолжать сессию через refresh.
	if err := s.repo.DeleteAllRefreshTokens(ctx, id); err != nil {
		return time.Time{}, err
	}
	// Access-токены удаление отозвало в базе (подняло их версию); здесь —
	// чтобы этот экземпляр перестал принимать их сразу. Ошибка не прерывает
	// удаление: отзыв догонит фоновая синхронизация.
	if err := s.revocations.Sync(ctx); err != nil {
		slog.ErrorContext(ctx, "sync token revocations", slog.Any("error", err))
	}
	return deletedAt.Add(s.cfg.RestoreWindow), nil
}
