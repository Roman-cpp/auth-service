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
	Name         string
	Phone        string
	CreatedAt    time.Time
	UpdatedAt    time.Time
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
