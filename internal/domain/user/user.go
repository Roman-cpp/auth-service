package user

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserID = string

type User struct {
	ID           UserID
	Email        string
	PasswordHash string
	Role         string
	Status       string
	LastName     string
	FirstName    string
	Patronymic   *string
	Phone        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  *time.Time
	DeletedAt    *time.Time
}

// DisplayName joins the first and last name into a single label, trimming the
// gap when one side is empty (e.g. "Admin" when only first_name is set).
func (u *User) DisplayName() string {
	return strings.TrimSpace(u.FirstName + " " + u.LastName)
}

type UserPreview struct {
	ID           UserID `json:"id"`
	Email        string `json:"email"`
	LastName     string `json:"last_name"`
	FirstName    string `json:"first_name"`
	Patronymic   *string `json:"patronymic"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuthUser is the user payload returned alongside tokens on login. Unlike
// UserPreview it exposes the RBAC role and a single display name, matching the
// shape consumers expect: {user_id, email, name, role}.
type AuthUser struct {
	UserID UserID `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
	Role   string `json:"role"`
}

// Profile is the full self-view returned by GET /users/me. It extends AuthUser
// with account status and timestamps.
type Profile struct {
	UserID      UserID     `json:"user_id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	Status      string     `json:"status"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func (u *User) UpdatePhone(phone string) {
	u.Phone = phone
	u.UpdatedAt = time.Now()
}

type RefreshToken struct {
	ID        string
	UserID    UserID
	Token     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Claims is the access-token payload. Standard fields (iss, aud, sub, exp,
// iat, nbf) live in RegisteredClaims; UserID mirrors sub for convenience and
// Role carries RBAC information for consumers.
type Claims struct {
	UserID UserID `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role,omitempty"`
	jwt.RegisteredClaims
}
