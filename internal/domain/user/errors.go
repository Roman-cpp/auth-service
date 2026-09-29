package user

import "errors"

// Ошибки хранилища.
var (
	ErrNotFound   = errors.New("user not found")
	ErrEmailTaken = errors.New("email already taken")
)

// Ошибки удалённого аккаунта. Отдаются только тому, кто предъявил верный
// пароль: до этого удалённый аккаунт неотличим от несуществующего, иначе
// эндпоинт входа сообщал бы, что адрес когда-то был зарегистрирован.
var (
	ErrAccountDeleted    = errors.New("account is deleted")
	ErrRestoreExpired    = errors.New("account restore window has expired")
	ErrAccountNotDeleted = errors.New("account is not deleted")
)

// ErrProtectedAccount: модератор не удаляет ни себя, ни других модераторов.
// Свой аккаунт удаляется обычным путём, через /users/{id}; модератора
// удалить некому — роли выше нет.
var ErrProtectedAccount = errors.New("account cannot be deleted by a moderator")

// ErrTwoFactorState: второй фактор уже включён или уже выключен — это
// состояние самого пользователя, а не сценария входа.
var ErrTwoFactorState = errors.New("two-factor authentication is already in the requested state")
