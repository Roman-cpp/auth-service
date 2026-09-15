package user

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserID = string

type User struct {
	ID               UserID
	Email            string
	PasswordHash     string
	LastName         string
	FirstName        string
	Patronymic       *string
	Phone            string
	EmailVerifiedAt  *time.Time
	TwoFactorEnabled bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeletedAt        *time.Time
}

// EmailVerified — единственный признак «аккаунтом можно пользоваться».
// Пока он false, пользователь заведён, но войти не может.
func (u *User) EmailVerified() bool {
	return u.EmailVerifiedAt != nil
}

type UserPreview struct {
	ID               UserID    `json:"id"`
	Email            string    `json:"email"`
	LastName         string    `json:"last_name"`
	FirstName        string    `json:"first_name"`
	Patronymic       *string   `json:"patronymic"`
	TwoFactorEnabled bool      `json:"two_factor_enabled"`
	CreatedAt        time.Time `json:"created_at"`
}

func NewUserPreview(u *User) *UserPreview {
	return &UserPreview{
		ID:               u.ID,
		Email:            u.Email,
		LastName:         u.LastName,
		FirstName:        u.FirstName,
		Patronymic:       u.Patronymic,
		TwoFactorEnabled: u.TwoFactorEnabled,
		CreatedAt:        u.CreatedAt,
	}
}

type RefreshToken struct {
	ID        string
	UserID    UserID
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// TokenType различает access-токен и промежуточный токен второго фактора.
// Оба подписаны одним секретом, поэтому без явного типа MFA-токен первого
// шага прошёл бы проверку как полноценный access — то есть второй фактор
// обходился бы предъявлением токена, выданного до его ввода.
type TokenType string

const (
	TokenTypeAccess TokenType = "access"
	TokenTypeMFA    TokenType = "mfa"
)

type Claims struct {
	UserID    UserID    `json:"user_id"`
	Email     string    `json:"email"`
	TokenType TokenType `json:"typ"`
	jwt.RegisteredClaims
}

// CodePurpose разделяет одноразовые коды по назначению: код подтверждения
// почты нельзя предъявить как второй фактор входа и наоборот.
type CodePurpose string

const (
	CodePurposeEmailVerify CodePurpose = "email_verify"
	CodePurposeMFALogin    CodePurpose = "mfa_login"
	CodePurposeMFAEnable   CodePurpose = "mfa_enable"
)

type AuthCode struct {
	ID         string
	UserID     UserID
	Purpose    CodePurpose
	CodeHash   string
	Attempts   int
	ExpiresAt  time.Time
	ConsumedAt *time.Time
	CreatedAt  time.Time
}

func (c *AuthCode) Consumed() bool {
	return c.ConsumedAt != nil
}

func (c *AuthCode) Expired(now time.Time) bool {
	return now.After(c.ExpiresAt)
}
