package auth

import "errors"

// Ошибки сценариев аутентификации. Живут в домене, а не в service: на них
// завязаны и HTTP-слой, и middleware, и тесты — это часть контракта домена,
// а не деталь конкретной реализации сервиса.
var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	// ErrRevocationsStale: список отозванных токенов давно не обновлялся
	// (база недоступна). Проверить токен честно нельзя — отказываем.
	ErrRevocationsStale = errors.New("token revocation list is stale")
	ErrEmailNotVerified = errors.New("email is not verified")
	ErrEmailVerified    = errors.New("email is already verified")
	// ErrPasswordUnchanged: новый пароль совпал с текущим. Отдельная ошибка,
	// а не тихий успех: пользователь, меняющий пароль после утечки, должен
	// узнать, что ничего не изменилось.
	ErrPasswordUnchanged = errors.New("new password matches the current one")
	// ErrPasswordChangeRequired: пароль верный, но временный — выдан
	// модератором. Сессии не будет, пока владелец не задаст свой.
	ErrPasswordChangeRequired = errors.New("temporary password must be changed")
	// ErrNoTemporaryPassword: замену временного пароля попросил аккаунт,
	// у которого пароль уже свой.
	ErrNoTemporaryPassword = errors.New("password is not temporary")
)

// Ошибки одноразовых кодов.
var (
	ErrCodeInvalid   = errors.New("invalid confirmation code")
	ErrCodeExpired   = errors.New("confirmation code expired")
	ErrCodeAttempts  = errors.New("too many invalid attempts")
	ErrResendTooSoon = errors.New("confirmation code was requested too recently")
)
