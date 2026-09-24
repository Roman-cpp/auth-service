package auth

import "github.com/krypton/auth-service/internal/domain/user"

// LoginResult описывает обе ветки входа. Tokens заполнены только если второй
// фактор не требуется; иначе клиент получает MFAToken и должен дойти до
// /auth/mfa/verify.
type LoginResult struct {
	User      *user.UserPreview
	Tokens    *TokenResponse
	MFAToken  string
	Challenge *CodeChallenge
}

func (r *LoginResult) MFARequired() bool {
	return r.Tokens == nil
}

// RegisterResult: сразу после регистрации сессии нет — есть только
// отправленный на почту код.
type RegisterResult struct {
	User      *user.UserPreview
	Challenge *CodeChallenge
}

// SessionResult — успешное завершение любого сценария, дающего сессию
// (подтверждение почты, ввод второго фактора).
type SessionResult struct {
	User   *user.UserPreview
	Tokens *TokenResponse
}
