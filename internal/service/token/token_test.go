package token_test

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/servicetest"
	"github.com/krypton/auth-service/internal/service/token"
)

// Главная проверка всей затеи: токен первого шага не должен открывать доступ
// к API. Раньше в Claims не было типа, и MFA-токен, подписанный тем же
// секретом, проходил валидацию как access — второй фактор обходился
// предъявлением токена, выданного ДО ввода кода.
func TestMFATokenIsRejectedAsAccessToken(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "mfa-typ@example.com")

	mfaToken, err := h.Tokens.IssueMFAToken(u)
	if err != nil {
		t.Fatalf("issue mfa token: %v", err)
	}

	if _, err := h.Tokens.ParseAccessToken(mfaToken); err != auth.ErrInvalidToken {
		t.Fatalf("MFA token accepted as access token (err = %v)", err)
	}
}

func TestAccessTokenIsRejectedAsMFAToken(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "access-typ@example.com")

	tokens, err := h.Tokens.IssueSession(t.Context(), u)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	if _, err := h.Tokens.ParseMFAToken(tokens.AccessToken); err != auth.ErrInvalidToken {
		t.Fatalf("access token accepted as MFA token (err = %v)", err)
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "roundtrip@example.com")

	tokens, err := h.Tokens.IssueSession(t.Context(), u)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	claims, err := h.Tokens.ParseAccessToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	if claims.UserID() != u.ID {
		t.Errorf("user id = %q, want %q", claims.UserID(), u.ID)
	}
	if claims.TokenType != auth.TokenTypeAccess {
		t.Errorf("token type = %q, want %q", claims.TokenType, auth.TokenTypeAccess)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "expired@example.com")

	cfg := h.JWTCfg
	cfg.AccessTokenTTL = -time.Minute
	tokens, err := token.NewIssuer(h.Repo, cfg).IssueSession(t.Context(), u)
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	if _, err := h.Tokens.ParseAccessToken(tokens.AccessToken); err != auth.ErrInvalidToken {
		t.Fatalf("expired token accepted (err = %v)", err)
	}
}

// alg=none — классическая подмена алгоритма. Проверяем, что список
// допустимых методов в парсере действительно её отсекает.
func TestUnsignedTokenIsRejected(t *testing.T) {
	h := servicetest.New(t)

	claims := &auth.Claims{
		TokenType: auth.TokenTypeAccess,
		Role:      user.RoleModerator,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	if _, err := h.Tokens.ParseAccessToken(unsigned); err != auth.ErrInvalidToken {
		t.Fatalf("alg=none token accepted (err = %v)", err)
	}
}

func TestTokenSignedWithAnotherSecretIsRejected(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "foreign@example.com")

	cfg := h.JWTCfg
	cfg.Secret = strings.Repeat("other-secret-", 4)
	foreign := token.NewIssuer(h.Repo, cfg)

	token, err := foreign.IssueMFAToken(u)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := h.Tokens.ParseMFAToken(token); err != auth.ErrInvalidToken {
		t.Fatalf("token signed with a foreign secret accepted (err = %v)", err)
	}
}
