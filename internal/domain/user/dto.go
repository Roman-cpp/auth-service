package user

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
// и ФИО без учёта регистра. Deleted — логически удалённые аккаунты вместо
// живых: из них модератор восстанавливает или удаляет навсегда.
type ListUsersFilter struct {
	Query   string
	Deleted bool
	Limit   int
	Offset  int
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
