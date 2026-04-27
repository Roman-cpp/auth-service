package user

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserID = string

type User struct {
	ID           UserID
	Email        string
	PasswordHash string
	LastName     string
	FirstName    string
	Patronymic   *string
	Phone        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

type UserPreview struct {
	ID           UserID
	Email        string
	LastName     string
	FirstName    string
	Patronymic   *string
	CreatedAt    time.Time
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

type Claims struct {
	UserID UserID `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}
