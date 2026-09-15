package user

import "time"

// Register — тело запроса регистрации. Валидация объявлена здесь же, рядом
// с доменным типом, чтобы HTTP-слой не заводил собственную копию структуры.
type Register struct {
	LastName   string  `json:"last_name"   validate:"required"`
	FirstName  string  `json:"first_name"  validate:"required"`
	Patronymic *string `json:"patronymic"`
	Email      string  `json:"email"       validate:"required,email"`
	// max=72 — предел bcrypt: более длинный пароль Go-реализация отвергает с ошибкой
	Password string `json:"password" validate:"required,min=8,max=72"`
}

// VerifyCode — подтверждение почты кодом из письма.
type VerifyCode struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code"  validate:"required,len=6,number"`
}

// ResendCode — повторная отправка кода подтверждения почты.
type ResendCode struct {
	Email string `json:"email" validate:"required,email"`
}

// MFAVerify — второй фактор входа. Идентификация идёт по mfa_token из куки,
// поэтому в теле только код.
type MFAVerify struct {
	Code string `json:"code" validate:"required,len=6,number"`
}

// PasswordConfirm — подтверждение паролем для операций со вторым фактором.
type PasswordConfirm struct {
	Password string `json:"password" validate:"required"`
}

type CreateDTO struct {
	LastName     string
	FirstName    string
	Patronymic   *string
	Email        string
	PasswordHash string
}

type Login struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// CodeChallenge — то, что нужно знать клиенту про выданный код: когда он
// протухнет и когда можно просить следующий. Сам код уходит только письмом.
type CodeChallenge struct {
	ExpiresAt     time.Time `json:"expires_at"`
	ResendAfterAt time.Time `json:"resend_after_at"`
}

// LoginResult описывает обе ветки входа. Tokens заполнены только если второй
// фактор не требуется; иначе клиент получает MFAToken и должен дойти до
// /auth/mfa/verify.
type LoginResult struct {
	User      *UserPreview
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
	User      *UserPreview
	Challenge *CodeChallenge
}

// SessionResult — успешное завершение любого сценария, дающего сессию
// (подтверждение почты, ввод второго фактора).
type SessionResult struct {
	User   *UserPreview
	Tokens *TokenResponse
}
