package servicetest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	authservice "github.com/krypton/auth-service/internal/service/auth"
	"github.com/krypton/auth-service/internal/service/otp"
	"github.com/krypton/auth-service/internal/service/qrlogin"
	"github.com/krypton/auth-service/internal/service/revocation"
	"github.com/krypton/auth-service/internal/service/token"
	userservice "github.com/krypton/auth-service/internal/service/user"
)

// SentMail — что сервис передал почтовику: письмо собирает mail-service,
// здесь виден только сценарий и код.
type SentMail struct {
	To      string
	Purpose auth.CodePurpose
	Code    string
}

// CaptureSender подменяет mail-service: запоминает вызовы SendCode.
type CaptureSender struct {
	mu   sync.Mutex
	sent []SentMail
	err  error
}

func (s *CaptureSender) SendCode(_ context.Context, to string, purpose auth.CodePurpose, code string, _ time.Duration, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, SentMail{To: to, Purpose: purpose, Code: code})
	return nil
}

func (s *CaptureSender) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *CaptureSender) Last(t *testing.T) SentMail {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sent) == 0 {
		t.Fatal("expected an email to be sent, got none")
	}
	return s.sent[len(s.sent)-1]
}

// Harness — сервисы, собранные поверх FakeRepo так же, как в main.
type Harness struct {
	Repo    *FakeRepo
	Mails   *CaptureSender
	Tokens  *token.Issuer
	Codes   *otp.Service
	Auth    *authservice.Service
	Users   *userservice.Service
	QR      *qrlogin.Service
	Revoked *revocation.List
	JWTCfg  config.JWTConfig
	Account config.AccountConfig
}

func New(t *testing.T) *Harness {
	t.Helper()

	repo := NewFakeRepo()
	sender := &CaptureSender{}

	jwtCfg := config.JWTConfig{
		Secret:          strings.Repeat("test-secret-", 4),
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		MFATokenTTL:     10 * time.Minute,
	}
	codesCfg := config.CodesConfig{
		TTL:            10 * time.Minute,
		ResendCooldown: time.Minute,
		MaxAttempts:    3,
	}
	accountCfg := config.AccountConfig{RestoreWindow: 365 * 24 * time.Hour}

	tokens := token.NewIssuer(repo, jwtCfg)
	codes := otp.NewService(repo, sender, codesCfg)
	revoked := revocation.NewList(repo)
	if err := revoked.Sync(context.Background()); err != nil {
		t.Fatalf("sync revocations: %v", err)
	}

	return &Harness{
		Repo:    repo,
		Mails:   sender,
		Tokens:  tokens,
		Codes:   codes,
		Auth:    authservice.NewService(repo, repo, tokens, codes, revoked, accountCfg),
		Users:   userservice.NewService(repo, repo, revoked, accountCfg),
		QR:      qrlogin.NewService(repo, repo, tokens, config.QRLoginConfig{TTL: 2 * time.Minute}),
		Revoked: revoked,
		JWTCfg:  jwtCfg,
		Account: accountCfg,
	}
}

// DeleteAccount удаляет аккаунт настоящим сценарием сервиса — вместе с
// отзывом сессий, а не правкой поля в фейковом репозитории.
func (h *Harness) DeleteAccount(t *testing.T, id user.UserID) time.Time {
	t.Helper()

	until, err := h.Users.DeleteUser(t.Context(), id)
	if err != nil {
		t.Fatalf("delete account: %v", err)
	}
	return until
}

// AgeDeletion отматывает момент удаления назад, чтобы не ждать окончания
// окна восстановления в реальном времени.
func (h *Harness) AgeDeletion(t *testing.T, id user.UserID, by time.Duration) {
	t.Helper()
	h.Repo.mu.Lock()
	defer h.Repo.mu.Unlock()

	u, ok := h.Repo.users[id]
	if !ok || u.DeletedAt == nil {
		t.Fatalf("account %s is not deleted", id)
	}
	aged := u.DeletedAt.Add(-by)
	u.DeletedAt = &aged
}

// Password — пароль аккаунтов, заведённых через RegisterVerified.
const Password = "correct-horse-battery"

// RegisterVerified проводит пользователя через полный путь регистрации —
// большинству тестов нужен уже готовый рабочий аккаунт.
func (h *Harness) RegisterVerified(t *testing.T, email string) *user.User {
	t.Helper()
	ctx := context.Background()

	if _, err := h.Auth.Register(ctx, &auth.Register{
		LastName: "Иванов", FirstName: "Иван", Email: email, Password: Password,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	code := h.Mails.Last(t).Code
	if _, err := h.Auth.VerifyEmail(ctx, &auth.VerifyCode{Email: email, Code: code}); err != nil {
		t.Fatalf("verify email: %v", err)
	}

	u, err := h.Repo.GetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	return u
}

// ExpireCode сдвигает срок жизни последнего кода в прошлое.
func (h *Harness) ExpireCode(t *testing.T, userID user.UserID, purpose auth.CodePurpose) {
	t.Helper()
	h.Repo.mu.Lock()
	defer h.Repo.mu.Unlock()

	for _, c := range h.Repo.codes {
		if c.UserID == userID && c.Purpose == purpose && !c.Consumed() {
			c.ExpiresAt = time.Now().Add(-time.Minute)
			return
		}
	}
	t.Fatalf("no active code for %s/%s", userID, purpose)
}

// ExpireQRLogin сдвигает срок заявки на вход по QR в прошлое.
func (h *Harness) ExpireQRLogin(t *testing.T, id string) {
	t.Helper()
	h.Repo.mu.Lock()
	defer h.Repo.mu.Unlock()

	q, ok := h.Repo.qr[id]
	if !ok {
		t.Fatalf("no qr login %s", id)
	}
	q.ExpiresAt = time.Now().Add(-time.Second)
}

// PassCooldown отматывает время выдачи кода назад, чтобы не ждать кулдаун
// в реальном времени.
func (h *Harness) PassCooldown(t *testing.T, userID user.UserID, purpose auth.CodePurpose) {
	t.Helper()
	h.Repo.mu.Lock()
	defer h.Repo.mu.Unlock()

	for _, c := range h.Repo.codes {
		if c.UserID == userID && c.Purpose == purpose {
			c.CreatedAt = c.CreatedAt.Add(-time.Hour)
		}
	}
}

// EnableTwoFactor проводит аккаунт через включение второго фактора целиком.
func (h *Harness) EnableTwoFactor(t *testing.T, u *user.User) {
	t.Helper()

	if _, err := h.Auth.StartEnableTwoFactor(t.Context(), u.ID, Password); err != nil {
		t.Fatalf("start enable 2fa: %v", err)
	}
	code := h.Mails.Last(t).Code
	if _, err := h.Auth.ConfirmEnableTwoFactor(t.Context(), u.ID, code); err != nil {
		t.Fatalf("confirm enable 2fa: %v", err)
	}
}

// Login — вход, который обязан пройти.
func (h *Harness) Login(t *testing.T, email, password string) *auth.LoginResult {
	t.Helper()

	res, err := h.Auth.Login(t.Context(), &auth.Login{Email: email, Password: password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return res
}
