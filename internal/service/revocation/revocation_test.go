package revocation_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/admin"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

// accessClaims выдаёт сессию и разбирает её access-токен — так проверяется
// ровно то, что потом увидит authn.
func accessClaims(t *testing.T, h *servicetest.Harness, u *user.User) *auth.Claims {
	t.Helper()
	tokens, err := h.Tokens.IssueSession(t.Context(), u)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	claims, err := h.Tokens.ParseAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	return claims
}

func checkToken(h *servicetest.Harness, c *auth.Claims) error {
	return h.Revoked.Check(c.UserID(), c.TokenVersion)
}

func TestAccessTokenCarriesRoleAndNoEmail(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "claims@example.com")

	c := accessClaims(t, h, u)
	if c.Role != user.RoleUser {
		t.Errorf("role = %q, want user", c.Role)
	}
	if c.Subject != u.ID {
		t.Errorf("sub = %q, want %q", c.Subject, u.ID)
	}
	if err := checkToken(h, c); err != nil {
		t.Errorf("fresh token rejected: %v", err)
	}
}

// Смена пароля гасит и уже выданные access-токены, а сессия, открытая
// следом, получает новую версию и работает.
func TestPasswordChangeRevokesAccessTokens(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "revoke-pw@example.com")
	old := accessClaims(t, h, u)

	result, err := h.Auth.ChangePassword(t.Context(), u.ID, &auth.ChangePassword{
		CurrentPassword: servicetest.Password, NewPassword: "brand-new-password",
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}

	if err := checkToken(h, old); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("old access token after password change: got %v, want ErrInvalidToken", err)
	}
	fresh, err := h.Tokens.ParseAccessToken(result.Tokens.AccessToken)
	if err != nil {
		t.Fatalf("parse new token: %v", err)
	}
	if err := checkToken(h, fresh); err != nil {
		t.Errorf("new session rejected right after password change: %v", err)
	}
}

// Роль в токене не переживает её смену: старый токен отзывается сразу после
// синхронизации (для изменений из консоли — не позже revocation.SyncInterval).
func TestRoleChangeRevokesAccessTokens(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "revoke-role@example.com")
	old := accessClaims(t, h, u)

	if _, err := admin.NewService(h.Repo, h.Users, h.Account).PromoteModerators(t.Context(), []string{u.Email}); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := h.Revoked.Sync(t.Context()); err != nil {
		t.Fatalf("sync: %v", err)
	}

	if err := checkToken(h, old); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("token with the old role: got %v, want ErrInvalidToken", err)
	}

	promoted, _ := h.Repo.GetByID(t.Context(), u.ID)
	if c := accessClaims(t, h, promoted); c.Role != user.RoleModerator || checkToken(h, c) != nil {
		t.Errorf("new token: role=%q check=%v", c.Role, checkToken(h, c))
	}
}

func TestAccountDeletionRevokesAccessTokens(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "revoke-del@example.com")
	old := accessClaims(t, h, u)

	h.DeleteAccount(t, u.ID)

	if err := checkToken(h, old); !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("token of a deleted account: got %v, want ErrInvalidToken", err)
	}
}

// Access-токен старого формата (без роли) не принимается: клиент молча
// обновит его через refresh и получит токен уже с ролью.
func TestAccessTokenWithoutRoleIsRejected(t *testing.T) {
	h := servicetest.New(t)

	legacy := &auth.Claims{
		TokenType: auth.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, legacy).SignedString([]byte(h.JWTCfg.Secret))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := h.Tokens.ParseAccessToken(signed); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("role-less access token accepted (err = %v)", err)
	}
}

// Пароль сменили, пока пользователь вводил второй фактор: MFA-токен первого
// шага выдан под старую версию и больше не действует.
func TestMFATokenInvalidatedByPasswordChange(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "mfa-pw@example.com")
	h.EnableTwoFactor(t, u)

	login, err := h.Auth.Login(t.Context(), &auth.Login{Email: u.Email, Password: servicetest.Password})
	if err != nil || !login.MFARequired() {
		t.Fatalf("login: %v, mfa=%v", err, login != nil && login.MFARequired())
	}
	code := h.Mails.Last(t).Code

	fresh, _ := h.Repo.GetByID(t.Context(), u.ID)
	if _, err := h.Auth.ChangePassword(t.Context(), fresh.ID, &auth.ChangePassword{CurrentPassword: servicetest.Password, NewPassword: "changed-meanwhile"}); err != nil {
		t.Fatalf("replace password: %v", err)
	}

	if _, err := h.Auth.VerifyMFA(t.Context(), login.MFAToken, code); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("MFA after password change: got %v, want ErrInvalidToken", err)
	}
}
