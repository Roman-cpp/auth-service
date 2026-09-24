package service

import (
	"context"
	"crypto/rand"
	"strings"

	"github.com/krypton/auth-service/internal/domain/user"
)

const (
	defaultListLimit = 50
	maxListLimit     = 200

	temporaryPasswordLength = 12
	// Без похожих друг на друга символов (0/O, 1/l/I): временный пароль
	// модератор передаёт пользователю вручную, часто — продиктовав.
	temporaryPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"
)

// AdminService — операции админки. Право на них проверяется до сервиса,
// в middleware по роли (authz.RequireRole); здесь — только правила самих
// операций.
type AdminService struct {
	repo user.Repository
}

func NewAdminService(repo user.Repository) *AdminService {
	return &AdminService{repo: repo}
}

func (s *AdminService) ListUsers(ctx context.Context, f user.ListUsersFilter) ([]*user.AdminUserView, int, error) {
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
		views[i] = user.NewAdminUserView(u)
	}
	return views, total, nil
}

// CreateUser заводит готовый к входу аккаунт: почта считается подтверждённой
// (её ввёл модератор), пароль — временный. Сам пароль возвращается один раз,
// передать его пользователю — забота модератора.
//
// Неподтверждённая заявка на тот же адрес перезаписывается, как и при
// повторной регистрации; подтверждённый аккаунт — нет, это ErrEmailTaken.
func (s *AdminService) CreateUser(ctx context.Context, actor user.UserID, req *user.AdminCreateUser) (*user.AdminCreateUserResult, error) {
	role := req.Role
	if role == "" {
		role = user.RoleUser
	}

	password, err := generateTemporaryPassword()
	if err != nil {
		return nil, err
	}
	hash, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	u, err := s.repo.Upsert(ctx, user.CreateDTO{
		LastName:           strings.TrimSpace(req.LastName),
		FirstName:          strings.TrimSpace(req.FirstName),
		Patronymic:         trimOptional(req.Patronymic),
		Email:              normalizeEmail(req.Email),
		PasswordHash:       hash,
		Role:               role,
		EmailVerified:      true,
		MustChangePassword: true,
		CreatedBy:          &actor,
	})
	if err != nil {
		return nil, err
	}

	return &user.AdminCreateUserResult{User: user.NewAdminUserView(u), TemporaryPassword: password}, nil
}

// PromoteModerators выдаёт роль модератора по списку адресов из конфига.
// Так появляется первый модератор: назначить его больше некому.
func (s *AdminService) PromoteModerators(ctx context.Context, emails []string) (int64, error) {
	normalized := make([]string, 0, len(emails))
	for _, e := range emails {
		if e = normalizeEmail(e); e != "" {
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
