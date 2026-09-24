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

// ForgotPassword — заявка на сброс пароля. Ответ одинаков для любого адреса,
// поэтому в нём нет ничего, кроме сроков кода.
type ForgotPassword struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPassword — второй шаг сброса: код из письма плюс новый пароль.
// Email нужен здесь, потому что сессии у сбрасывающего пароль нет по
// определению — опознать его больше нечем.
type ResetPassword struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code"  validate:"required,len=6,number"`
	// Ограничения те же, что при регистрации: max=72 — предел bcrypt.
	Password string `json:"password" validate:"required,min=8,max=72"`
}

// ChangePassword — смена пароля изнутри сессии. Текущий пароль обязателен:
// перехваченная сессия не должна давать права сменить пароль, иначе владельца
// аккаунта выдавливают из него в один запрос.
type ChangePassword struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password"     validate:"required,min=8,max=72"`
}

// RestoreAccount — возврат удалённого аккаунта. Сессии у владельца нет,
// удаление её погасило, поэтому опознание идёт по email и паролю.
type RestoreAccount struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// ChangeInitialPassword — замена временного пароля, выданного модератором.
// Сессии у пользователя ещё нет (вход с временным паролем её не открывает),
// поэтому опознание — по email и временному паролю.
type ChangeInitialPassword struct {
	Email       string `json:"email"        validate:"required,email"`
	Password    string `json:"password"     validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=72"`
}

// AdminCreateUser — заведение аккаунта модератором. Пароля в запросе нет:
// временный пароль генерирует сервис и отдаёт модератору один раз.
type AdminCreateUser struct {
	LastName   string  `json:"last_name"  validate:"required,max=255"`
	FirstName  string  `json:"first_name" validate:"required,max=255"`
	Patronymic *string `json:"patronymic" validate:"omitempty,max=255"`
	Email      string  `json:"email"      validate:"required,email,max=255"`
	// Пустая роль — обычный пользователь.
	Role Role `json:"role" validate:"omitempty,oneof=user moderator"`
}

// AdminCreateUserResult: временный пароль виден только в этом ответе —
// в базе лежит лишь его хеш.
type AdminCreateUserResult struct {
	User              *AdminUserView `json:"user"`
	TemporaryPassword string         `json:"temporary_password"`
}

// ListUsersFilter — постраничная выборка для админки. Query ищет по email
// и ФИО без учёта регистра.
type ListUsersFilter struct {
	Query  string
	Limit  int
	Offset int
}

type CreateDTO struct {
	LastName     string
	FirstName    string
	Patronymic   *string
	Email        string
	PasswordHash string
	Role         Role
	// EmailVerified: адрес ввёл модератор — подтверждать его кодом незачем.
	EmailVerified      bool
	MustChangePassword bool
	CreatedBy          *UserID
}

type Login struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// TokenResponse — выданная пара токенов. Клиенту она уходит только
// httpOnly-куками (CookieManager.SetSessionCookies), поэтому JSON-тегов
// нет: в теле ответа токенам делать нечего.
type TokenResponse struct {
	AccessToken  string `json:"-"`
	RefreshToken string `json:"-"`
	ExpiresIn    int64  `json:"-"`
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
