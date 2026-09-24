package service

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krypton/auth-service/internal/domain/user"
)

// accessClaims выдаёт сессию и разбирает её access-токен — так проверяется
// ровно то, что потом увидит authn.
func (h *harness) accessClaims(t *testing.T, u *user.User) *user.Claims {
	t.Helper()
	tokens, err := h.tokens.IssueSession(t.Context(), u)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	claims, err := h.tokens.ParseAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	return claims
}

func (h *harness) checkToken(c *user.Claims) error {
	return h.revoked.Check(c.UserID(), c.TokenVersion)
}

func TestAccessTokenCarriesRoleAndNoEmail(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "claims@example.com")

	c := h.accessClaims(t, u)
	if c.Role != user.RoleUser {
		t.Errorf("role = %q, want user", c.Role)
	}
	if c.Subject != u.ID {
		t.Errorf("sub = %q, want %q", c.Subject, u.ID)
	}
	if err := h.checkToken(c); err != nil {
		t.Errorf("fresh token rejected: %v", err)
	}
}

// Смена пароля гасит и уже выданные access-токены, а сессия, открытая
// следом, получает новую версию и работает.
func TestPasswordChangeRevokesAccessTokens(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "revoke-pw@example.com")
	old := h.accessClaims(t, u)

	result, err := h.auth.ChangePassword(t.Context(), u.ID, &user.ChangePassword{
		CurrentPassword: testPassword, NewPassword: "brand-new-password",
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}

	if err := h.checkToken(old); !errors.Is(err, user.ErrInvalidToken) {
		t.Errorf("old access token after password change: got %v, want ErrInvalidToken", err)
	}
	fresh, err := h.tokens.ParseAccessToken(result.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("parse new token: %v", err)
	}
	if err := h.checkToken(fresh); err != nil {
		t.Errorf("new session rejected right after password change: %v", err)
	}
}

// Роль в токене не переживает её смену: старый токен отзывается сразу после
// синхронизации (для изменений из консоли — не позже RevocationSyncInterval).
func TestRoleChangeRevokesAccessTokens(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "revoke-role@example.com")
	old := h.accessClaims(t, u)

	if _, err := NewAdminService(h.repo).PromoteModerators(t.Context(), []string{u.Email}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := h.revoked.Sync(t.Context()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	if err := h.checkToken(old); !errors.Is(err, user.ErrInvalidToken) {
		t.Errorf("token with the old role: got %v, want ErrInvalidToken", err)
	}

	promoted, _ := h.repo.GetByID(t.Context(), u.ID)
	if c := h.accessClaims(t, promoted); c.Role != user.RoleModerator || h.checkToken(c) != nil {
		t.Errorf("new token: role=%q check=%v", c.Role, h.checkToken(c))
	}
}

func TestAccountDeletionRevokesAccessTokens(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "revoke-del@example.com")
	old := h.accessClaims(t, u)

	h.deleteAccount(t, u.ID)

	if err := h.checkToken(old); !errors.Is(err, user.ErrInvalidToken) {
		t.Errorf("token of a deleted account: got %v, want ErrInvalidToken", err)
	}
}

// Список, который давно не обновлялся, не принимает ни одного токена:
// пропущенный за это время отзыв иначе остался бы незамеченным.
func TestStaleRevocationListFailsClosed(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "stale@example.com")
	c := h.accessClaims(t, u)

	h.revoked.now = func() time.Time { return time.Now().Add(revocationMaxStaleness + time.Second) }

	if err := h.checkToken(c); !errors.Is(err, user.ErrRevocationsStale) {
		t.Errorf("got %v, want ErrRevocationsStale", err)
	}
}

// Access-токен старого формата (без роли) не принимается: клиент молча
// обновит его через refresh и получит токен уже с ролью.
func TestAccessTokenWithoutRoleIsRejected(t *testing.T) {
	h := newHarness(t)

	legacy := &user.Claims{
		TokenType: user.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacy).SignedString([]byte(h.jwtCfg.Secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := h.tokens.ParseAccessToken(signed); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("role-less access token accepted (err = %v)", err)
	}
}

// Пароль сменили, пока пользователь вводил второй фактор: MFA-токен первого
// шага выдан под старую версию и больше не действует.
func TestMFATokenInvalidatedByPasswordChange(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "mfa-pw@example.com")
	enableTwoFactor(t, h, u)

	login, err := h.auth.Login(t.Context(), &user.Login{Email: u.Email, Password: testPassword})
	if err != nil || !login.MFARequired() {
		t.Fatalf("login: %v, mfa=%v", err, login != nil && login.MFARequired())
	}
	code := h.mails.last(t).code

	fresh, _ := h.repo.GetByID(t.Context(), u.ID)
	if err := h.auth.replacePassword(t.Context(), fresh, "changed-meanwhile"); err != nil {
		t.Fatalf("replace password: %v", err)
	}

	if _, err := h.auth.VerifyMFA(t.Context(), login.MFAToken, code); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("MFA after password change: got %v, want ErrInvalidToken", err)
	}
}
