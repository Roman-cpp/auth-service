package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
)

// Issuer — единственное место, где выпускаются и разбираются токены.
type Issuer struct {
	repo auth.Repository
	cfg  config.JWTConfig
}

func NewIssuer(repo auth.Repository, cfg config.JWTConfig) *Issuer {
	return &Issuer{repo: repo, cfg: cfg}
}

// IssueSession выдаёт пару access + refresh. Вызывается только после того,
// как пройдены ВСЕ факторы: пароль, подтверждённая почта и, если включена,
// двухфакторная проверка.
func (t *Issuer) IssueSession(ctx context.Context, u *user.User) (*auth.TokenResponse, error) {
	accessToken, expiresAt, err := t.sign(u, auth.TokenTypeAccess, t.cfg.AccessTokenTTL)
	if err != nil {
		return nil, err
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return nil, err
	}
	if err := t.repo.SaveRefreshToken(ctx, u.ID, HashRefresh(refreshToken), time.Now().Add(t.cfg.RefreshTokenTTL)); err != nil {
		return nil, err
	}

	return &auth.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(time.Until(expiresAt).Seconds()),
	}, nil
}

// IssueMFAToken выдаёт промежуточный токен между вводом пароля и вводом кода.
// Он подтверждает только первый фактор и по типу отличается от access —
// предъявить его вместо access-токена нельзя.
func (t *Issuer) IssueMFAToken(u *user.User) (string, error) {
	token, _, err := t.sign(u, auth.TokenTypeMFA, t.cfg.MFATokenTTL)
	return token, err
}

func (t *Issuer) ParseAccessToken(token string) (*auth.Claims, error) {
	return t.parse(token, auth.TokenTypeAccess)
}

func (t *Issuer) ParseMFAToken(token string) (*auth.Claims, error) {
	return t.parse(token, auth.TokenTypeMFA)
}

func (t *Issuer) sign(u *user.User, typ auth.TokenType, ttl time.Duration) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(ttl)
	claims := &auth.Claims{
		TokenType:    typ,
		TokenVersion: u.TokenVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	// Роль — только в access-токене: MFA-токену первого шага она не нужна.
	if typ == auth.TokenTypeAccess {
		claims.Role = u.Role
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(t.cfg.Secret))
	return signed, expiresAt, err
}

func (t *Issuer) parse(tokenStr string, want auth.TokenType) (*auth.Claims, error) {
	claims := &auth.Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims,
		func(*jwt.Token) (any, error) { return []byte(t.cfg.Secret), nil },
		// Алгоритм фиксируем списком, а не проверкой внутри keyfunc:
		// так библиотека отсекает и alg=none, и подмену HS/RS.
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !token.Valid {
		return nil, auth.ErrInvalidToken
	}
	// Без этой проверки MFA-токен первого шага прошёл бы как access-токен,
	// то есть второй фактор обходился бы полностью.
	if claims.TokenType != want {
		return nil, auth.ErrInvalidToken
	}
	if claims.Subject == "" {
		return nil, auth.ErrInvalidToken
	}
	// Access-токены, выданные до появления роли в токене, роли не несут.
	// Отказ здесь — это 401 и тихий refresh на клиенте, после которого
	// токен приходит уже с ролью; «пустая роль = обычный пользователь»
	// на 15 минут лишила бы модератора админки.
	if want == auth.TokenTypeAccess && !claims.Role.Valid() {
		return nil, auth.ErrInvalidToken
	}
	return claims, nil
}

func generateRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashRefresh: в БД хранится только SHA-256 от токена — утечка таблицы
// refresh_tokens не даёт угнать сессии. Быстрый хеш здесь уместен (в отличие
// от одноразовых кодов): в токене 256 бит энтропии, перебирать нечего.
func HashRefresh(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
