package service

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/mailer"
)

// Код вытаскивается из готового письма, а не подсматривается в сервисе:
// так тесты заодно проверяют, что он вообще доезжает до текста письма.
var codeInMail = regexp.MustCompile(`\b(\d{6})\b`)

type sentMail struct {
	to      string
	subject string
	code    string
}

type captureSender struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

func (s *captureSender) Send(_ context.Context, msg mailer.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.err != nil {
		return s.err
	}
	m := sentMail{to: msg.To, subject: msg.Subject}
	if match := codeInMail.FindStringSubmatch(msg.Text); match != nil {
		m.code = match[1]
	}
	s.sent = append(s.sent, m)
	return nil
}

func (s *captureSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func (s *captureSender) last(t *testing.T) sentMail {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.sent) == 0 {
		t.Fatal("expected an email to be sent, got none")
	}
	return s.sent[len(s.sent)-1]
}

type harness struct {
	repo   *fakeRepo
	mails  *captureSender
	tokens *TokenIssuer
	codes  *CodeService
	auth   *AuthService
	jwtCfg config.JWTConfig
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	repo := newFakeRepo()
	sender := &captureSender{}

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

	tokens := NewTokenIssuer(repo, jwtCfg)
	codes := NewCodeService(repo, mailer.New(sender, "Nexus"), codesCfg)

	return &harness{
		repo:   repo,
		mails:  sender,
		tokens: tokens,
		codes:  codes,
		auth:   NewAuthService(repo, tokens, codes),
		jwtCfg: jwtCfg,
	}
}

const testPassword = "correct-horse-battery"

// registerVerified проводит пользователя через полный путь регистрации —
// большинству тестов нужен уже готовый рабочий аккаунт.
func (h *harness) registerVerified(t *testing.T, email string) *user.User {
	t.Helper()
	ctx := context.Background()

	if _, err := h.auth.Register(ctx, &user.Register{
		LastName: "Иванов", FirstName: "Иван", Email: email, Password: testPassword,
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	code := h.mails.last(t).code
	if _, err := h.auth.VerifyEmail(ctx, &user.VerifyCode{Email: email, Code: code}); err != nil {
		t.Fatalf("verify email: %v", err)
	}

	u, err := h.repo.GetByEmail(ctx, email)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	return u
}

// expireCode сдвигает срок жизни последнего кода в прошлое.
func (h *harness) expireCode(t *testing.T, userID user.UserID, purpose user.CodePurpose) {
	t.Helper()
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()

	for _, c := range h.repo.codes {
		if c.UserID == userID && c.Purpose == purpose && !c.Consumed() {
			c.ExpiresAt = time.Now().Add(-time.Minute)
			return
		}
	}
	t.Fatalf("no active code for %s/%s", userID, purpose)
}

// passCooldown отматывает время выдачи кода назад, чтобы не ждать кулдаун
// в реальном времени.
func (h *harness) passCooldown(t *testing.T, userID user.UserID, purpose user.CodePurpose) {
	t.Helper()
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()

	for _, c := range h.repo.codes {
		if c.UserID == userID && c.Purpose == purpose {
			c.CreatedAt = c.CreatedAt.Add(-time.Hour)
		}
	}
}
