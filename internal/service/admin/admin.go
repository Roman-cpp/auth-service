package admin

import (
	"context"
	"crypto/rand"
	"strings"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/platform/passhash"
)

const (
	defaultListLimit = 50
	maxListLimit     = 200

	temporaryPasswordLength = 12
	// Без похожих друг на друга символов (0/O, 1/l/I): временный пароль
	// модератор передаёт пользователю вручную, часто — продиктовав.
	temporaryPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
)

// Service — операции админки. Право на них проверяется до сервиса,
// в middleware по роли (authz.RequireModerator); здесь — только правила самих
// операций.
type Service struct {
	repo     user.Repository
	accounts AccountDeleter
	cfg      config.AccountConfig
}

// AccountDeleter — логическое удаление вместе с отзывом сессий. Его уже
// делает сервис пользователя для удаления своего аккаунта; админка
// переиспользует тот же сценарий, а не повторяет его.
type AccountDeleter interface {
	DeleteUser(ctx context.Context, id user.UserID) (time.Time, error)
}

func NewService(repo user.Repository, accounts AccountDeleter, cfg config.AccountConfig) *Service {
	return &Service{repo: repo, accounts: accounts, cfg: cfg}
}

func (s *Service) ListUsers(ctx context.Context, f user.ListUsersFilter) ([]*user.AdminUserView, int, error) {
	if f.Limit <= 0 {
		f.Limit = defaultListLimit
	}
	f.Limit = min(f.Limit, maxListLimit)
	f.Offset = max(f.Offset, 0)
	f.Query = strings.TrimSpace(f.Query)

	users, total, err := s.repo.ListUsers(ctx, f)
	if err != nil {
		return nil, 0, err
	}

	views := make([]*user.AdminUserView, len(users))
	for i, u := range users {
		views[i] = user.NewAdminUserView(u, s.cfg.RestoreWindow)
	}
	return views, total, nil
}

// CreateUser заводит готовый к входу аккаунт: почта считается подтверждённой
// (её ввёл модератор), пароль — временный. Сам пароль возвращается один раз,
// передать его пользователю — забота модератора.
//
// Неподтверждённая заявка на тот же адрес перезаписывается, как и при
// повторной регистрации; подтверждённый аккаунт — нет, это ErrEmailTaken.
func (s *Service) CreateUser(ctx context.Context, actor user.UserID, req *user.AdminCreateUser) (*user.AdminCreateUserResult, error) {
	role := req.Role
	if role == "" {
		role = user.RoleUser
	}

	password, err := generateTemporaryPassword()
	if err != nil {
		return nil, err
	}
	hash, err := passhash.Hash(password)
	if err != nil {
		return nil, err
	}

	u, err := s.repo.Upsert(ctx, user.CreateDTO{
		LastName:           strings.TrimSpace(req.LastName),
		FirstName:          strings.TrimSpace(req.FirstName),
		Patronymic:         trimOptional(req.Patronymic),
		Email:              user.NormalizeEmail(req.Email),
		PasswordHash:       hash,
		Role:               role,
		EmailVerified:      true,
		MustChangePassword: true,
		CreatedBy:          &actor,
	})
	if err != nil {
		return nil, err
	}

	return &user.AdminCreateUserResult{User: user.NewAdminUserView(u, s.cfg.RestoreWindow), TemporaryPassword: password}, nil
}

// DeleteUser — первый шаг удаления: аккаунт помечается удалённым, его
// сессии гаснут, адрес освобождается. До конца окна восстановления его
// можно вернуть (RestoreUser) или удалить навсегда (PurgeUser).
func (s *Service) DeleteUser(ctx context.Context, actor, id user.UserID) (*user.AdminUserView, error) {
	target, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := protect(actor, target); err != nil {
		return nil, err
	}

	if _, err := s.accounts.DeleteUser(ctx, id); err != nil {
		return nil, err
	}
	return s.view(ctx, id)
}

// RestoreUser снимает пометку удаления. Правила те же, что при
// восстановлении владельцем: окно не истекло, адрес не занят новым
// подтверждённым аккаунтом (иначе ErrEmailTaken). Сессию никому не выдаёт.
func (s *Service) RestoreUser(ctx context.Context, id user.UserID) (*user.AdminUserView, error) {
	target, err := s.repo.GetByIDWithDeleted(ctx, id)
	if err != nil {
		return nil, err
	}
	if target.DeletedAt == nil {
		return nil, user.ErrAccountNotDeleted
	}
	// Окно считается так же, как у владельца: после него аккаунт уже
	// неотличим от несуществующего, даже если уборщик до него не дошёл.
	if time.Since(*target.DeletedAt) >= s.cfg.RestoreWindow {
		return nil, user.ErrRestoreExpired
	}

	if err := s.repo.Restore(ctx, id); err != nil {
		return nil, err
	}
	return s.view(ctx, id)
}

// PurgeUser — второй шаг: физическое удаление уже удалённого логически
// аккаунта. Живой аккаунт так не удалить — сначала DeleteUser. Данные
// пользователя в других сервисах не трогаются.
func (s *Service) PurgeUser(ctx context.Context, actor, id user.UserID) error {
	target, err := s.repo.GetByIDWithDeleted(ctx, id)
	if err != nil {
		return err
	}
	if target.DeletedAt == nil {
		return user.ErrAccountNotDeleted
	}
	// Модератор, удаливший свой аккаунт сам, остаётся под защитой: навсегда
	// его унесёт только уборщик по окончании окна.
	if err := protect(actor, target); err != nil {
		return err
	}

	return s.repo.HardDelete(ctx, id)
}

func (s *Service) view(ctx context.Context, id user.UserID) (*user.AdminUserView, error) {
	u, err := s.repo.GetByIDWithDeleted(ctx, id)
	if err != nil {
		return nil, err
	}
	return user.NewAdminUserView(u, s.cfg.RestoreWindow), nil
}

// protect: модератор не удаляет ни себя, ни других модераторов.
func protect(actor user.UserID, target *user.User) error {
	if target.ID == actor || target.Role == user.RoleModerator {
		return user.ErrProtectedAccount
	}
	return nil
}

// PromoteModerators выдаёт роль модератора по списку адресов из конфига.
// Так появляется первый модератор: назначить его больше некому.
func (s *Service) PromoteModerators(ctx context.Context, emails []string) (int64, error) {
	normalized := make([]string, 0, len(emails))
	for _, e := range emails {
		if e = user.NormalizeEmail(e); e != "" {
			normalized = append(normalized, e)
		}
	}
	if len(normalized) == 0 {
		return 0, nil
	}
	return s.repo.PromoteModerators(ctx, normalized)
}

// generateTemporaryPassword: rand.Text не подходит — в его алфавите есть
// путаемые символы.
func generateTemporaryPassword() (string, error) {
	var b strings.Builder
	b.Grow(temporaryPasswordLength)
	buf := make([]byte, temporaryPasswordLength)
	// Байты вне диапазона, кратного длине алфавита, отбрасываются — иначе
	// из-за остатка по модулю первые символы алфавита выпадали бы чаще.
	limit := byte(256 - 256%len(temporaryPasswordAlphabet))
	for b.Len() < temporaryPasswordLength {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, c := range buf {
			if c >= limit || b.Len() == temporaryPasswordLength {
				continue
			}
			b.WriteByte(temporaryPasswordAlphabet[int(c)%len(temporaryPasswordAlphabet)])
		}
	}
	return b.String(), nil
}

func trimOptional(s *string) *string {
	if s == nil {
		return nil
	}
	t := strings.TrimSpace(*s)
	if t == "" {
		return nil
	}
	return &t
}
