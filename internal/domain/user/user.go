package user

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserID = string

// Role — уровень доступа. Модератор ведёт админку: видит всех пользователей
// и заводит новые аккаунты. Отдельной роли администратора нет.
type Role string

const (
	RoleUser      Role = "user"
	RoleModerator Role = "moderator"
)

func (r Role) Valid() bool {
	return r == RoleUser || r == RoleModerator
}

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
	Role             Role
	// MustChangePassword: пароль выдан модератором и владельцу не принадлежит.
	// Пока флаг стоит, вход не открывает сессию — сначала смена пароля.
	MustChangePassword bool
	// CreatedBy — модератор, заведший аккаунт; nil — зарегистрировался сам.
	CreatedBy *UserID
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
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
	Role             Role      `json:"role"`
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
		Role:             u.Role,
		CreatedAt:        u.CreatedAt,
	}
}

// AdminUserView — пользователь глазами админки: к превью добавлено то, что
// нужно модератору и не нужно самому пользователю.
type AdminUserView struct {
	UserPreview
	EmailVerified      bool    `json:"email_verified"`
	MustChangePassword bool    `json:"must_change_password"`
	CreatedBy          *UserID `json:"created_by"`
}

func NewAdminUserView(u *User) *AdminUserView {
	return &AdminUserView{
		UserPreview:        *NewUserPreview(u),
		EmailVerified:      u.EmailVerified(),
		MustChangePassword: u.MustChangePassword,
		CreatedBy:          u.CreatedBy,
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
	CodePurposeEmailVerify   CodePurpose = "email_verify"
	CodePurposeMFALogin      CodePurpose = "mfa_login"
	CodePurposeMFAEnable     CodePurpose = "mfa_enable"
	CodePurposePasswordReset CodePurpose = "password_reset"
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
