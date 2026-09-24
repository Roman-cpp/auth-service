package auth

import (
	"time"

	"github.com/krypton/auth-service/internal/domain/user"
)

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
	UserID     user.UserID
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

// CodeChallenge — то, что нужно знать клиенту про выданный код: когда он
// протухнет и когда можно просить следующий. Сам код уходит только письмом.
type CodeChallenge struct {
	ExpiresAt     time.Time `json:"expires_at"`
	ResendAfterAt time.Time `json:"resend_after_at"`
}
