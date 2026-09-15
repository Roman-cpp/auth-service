package user

import "errors"

// Ошибки хранилища.
var (
	ErrNotFound   = errors.New("user not found")
	ErrEmailTaken = errors.New("email already taken")
	ErrDeleted    = errors.New("user already deleted")
)

// Ошибки сценариев аутентификации. Живут в домене, а не в service: на них
// завязаны и HTTP-слой, и middleware, и тесты — это часть контракта домена,
// а не деталь конкретной реализации сервиса.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrEmailNotVerified   = errors.New("email is not verified")
	ErrEmailVerified      = errors.New("email is already verified")
)

// Ошибки одноразовых кодов.
var (
	ErrCodeInvalid    = errors.New("invalid confirmation code")
	ErrCodeExpired    = errors.New("confirmation code expired")
	ErrCodeAttempts   = errors.New("too many invalid attempts")
	ErrResendTooSoon  = errors.New("confirmation code was requested too recently")
	ErrTwoFactorState = errors.New("two-factor authentication is already in the requested state")
)
