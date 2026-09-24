package auth

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

type Login struct {
	Email    string `json:"email"    validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
