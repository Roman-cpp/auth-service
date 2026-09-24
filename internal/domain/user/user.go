// Package user — пользователь как ресурс: сама сущность, её представления
// для API и админки, хранилище. Всё, что относится ко входу и сессиям
// (токены, одноразовые коды, сценарии аутентификации), — в пакете auth.
package user

import "time"

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
	// TokenVersion поднимает база (триггер) при смене роли, пароля и
	// удалении. Токены с версией ниже текущей считаются отозванными
	// (см. пакет auth).
	TokenVersion int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
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
