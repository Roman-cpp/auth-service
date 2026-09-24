package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/krypton/auth-service/internal/domain/user"
)

// TokenType различает access-токен и промежуточный токен второго фактора.
// Оба подписаны одним секретом, поэтому без явного типа MFA-токен первого
// шага прошёл бы проверку как полноценный access — то есть второй фактор
// обходился бы предъявлением токена, выданного до его ввода.
type TokenType string

const (
	TokenTypeAccess TokenType = "access"
	TokenTypeMFA    TokenType = "mfa"
)

// Claims — содержимое JWT. Идентификатор пользователя — стандартный sub.
// Почты и прочих персональных данных здесь нет: payload подписан, но не
// зашифрован, и прочитать его может любой, у кого оказался токен.
type Claims struct {
	TokenType TokenType `json:"typ"`
	// Role есть только в access-токене. Держать её в токене безопасно,
	// потому что смена роли поднимает TokenVersion и старые токены отзываются.
	Role user.Role `json:"role,omitempty"`
	// TokenVersion — версия токенов пользователя на момент выдачи.
	TokenVersion int64 `json:"ver"`
	jwt.RegisteredClaims
}

func (c *Claims) UserID() user.UserID {
	return c.Subject
}

type RefreshToken struct {
	ID        string
	UserID    user.UserID
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// TokenResponse — выданная пара токенов. Клиенту она уходит только
// httpOnly-куками (CookieManager.SetSessionCookies), поэтому JSON-тегов
// нет: в теле ответа токенам делать нечего.
type TokenResponse struct {
	AccessToken  string `json:"-"`
	RefreshToken string `json:"-"`
	ExpiresIn    int64  `json:"-"`
}
