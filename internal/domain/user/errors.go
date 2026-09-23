package user

import "errors"

// Ошибки хранилища.
var (
	ErrNotFound   = errors.New("user not found")
	ErrEmailTaken = errors.New("email already taken")
)

// Ошибки сценариев аутентификации. Живут в домене, а не в service: на них
// завязаны и HTTP-слой, и middleware, и тесты — это часть контракта домена,
// а не деталь конкретной реализации сервиса.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrEmailNotVerified   = errors.New("email is not verified")
	ErrEmailVerified      = errors.New("email is already verified")
	// ErrPasswordUnchanged: новый пароль совпал с текущим. Отдельная ошибка,
	// а не тихий успех: пользователь, меняющий пароль после утечки, должен
	// узнать, что ничего не изменилось.
	ErrPasswordUnchanged = errors.New("new password matches the current one")
)

// Ошибки удалённого аккаунта. Отдаются только тому, кто предъявил верный
// пароль: до этого удалённый аккаунт неотличим от несуществующего, иначе
// эндпоинт входа сообщал бы, что адрес когда-то был зарегистрирован.
var (
	ErrAccountDeleted    = errors.New("account is deleted")
	ErrRestoreExpired    = errors.New("account restore window has expired")
	ErrAccountNotDeleted = errors.New("account is not deleted")
)

// Ошибки одноразовых кодов.
var (
	ErrCodeInvalid    = errors.New("invalid confirmation code")
	ErrCodeExpired    = errors.New("confirmation code expired")
	ErrCodeAttempts   = errors.New("too many invalid attempts")
	ErrResendTooSoon  = errors.New("confirmation code was requested too recently")
	ErrTwoFactorState = errors.New("two-factor authentication is already in the requested state")
)
