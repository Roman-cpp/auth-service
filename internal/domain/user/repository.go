package user

import (
	"context"
	"time"
)

type Repository interface {
	// Upsert заводит пользователя либо перезаписывает ещё не подтверждённую
	// заявку с тем же email. Подтверждённый аккаунт перезаписан не будет —
	// вернётся ErrEmailTaken.
	Upsert(ctx context.Context, dto CreateDTO) (*User, error)
	GetByID(ctx context.Context, id UserID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	// GetDeletedByEmail возвращает самый свежий удалённый аккаунт с этим
	// адресом. Удалённых строк на один адрес может быть несколько: удалил,
	// зарегистрировался заново, удалил снова.
	GetDeletedByEmail(ctx context.Context, email string) (*User, error)
	// SoftDelete помечает аккаунт удалённым и отдаёт момент удаления —
	// от него отсчитывается окно восстановления.
	SoftDelete(ctx context.Context, id UserID) (time.Time, error)
	// Restore снимает пометку удаления. Возвращает ErrEmailTaken, если
	// адрес успел занять новый живой аккаунт: двух живых с одним email
	// не допускает частичный уникальный индекс.
	Restore(ctx context.Context, id UserID) error
	// PurgeDeletedUsers физически удаляет аккаунты, удалённые раньше
	// указанного момента: окно восстановления кончилось. Коды и
	// refresh-токены уходят каскадом.
	PurgeDeletedUsers(ctx context.Context, before time.Time) (int64, error)
	MarkEmailVerified(ctx context.Context, id UserID) error
	SetTwoFactorEnabled(ctx context.Context, id UserID, enabled bool) error
	// UpdatePassword заодно снимает MustChangePassword: любой пароль,
	// заданный самим владельцем, временным уже не является.
	UpdatePassword(ctx context.Context, id UserID, passwordHash string) error
	// ListUsers — живые аккаунты для админки, свежие сначала, и общее число
	// подходящих под фильтр.
	ListUsers(ctx context.Context, f ListUsersFilter) ([]*User, int, error)
	// PromoteModerators выдаёт роль модератора живым аккаунтам с этими
	// адресами и возвращает, сколько строк изменилось.
	PromoteModerators(ctx context.Context, emails []string) (int64, error)

	// TokenRevocations — текущие версии токенов пользователей, у которых
	// недавно что-то отзывалось. Таблицу пополняет триггер в базе.
	TokenRevocations(ctx context.Context) (map[UserID]int64, error)
	// DeleteStaleTokenRevocations убирает записи старше before: все токены
	// со старыми версиями к этому моменту уже истекли сами.
	DeleteStaleTokenRevocations(ctx context.Context, before time.Time) error

	// IssueAuthCode гасит предыдущий живой код той же пары
	// (пользователь, назначение) и записывает новый.
	IssueAuthCode(ctx context.Context, userID UserID, purpose CodePurpose, codeHash string, expiresAt time.Time) (*AuthCode, error)
	// LatestAuthCode возвращает последний выданный код — в том числе уже
	// погашенный: по нему считается кулдаун на повторную отправку.
	LatestAuthCode(ctx context.Context, userID UserID, purpose CodePurpose) (*AuthCode, error)
	IncrementAuthCodeAttempts(ctx context.Context, id string) (int, error)
	// ConsumeAuthCode гасит код и возвращает ErrNotFound, если он уже был
	// погашен: так параллельная проверка одного кода срабатывает один раз.
	ConsumeAuthCode(ctx context.Context, id string) error
	DeleteExpiredAuthCodes(ctx context.Context) error

	SaveRefreshToken(ctx context.Context, userID UserID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	DeleteAllRefreshTokens(ctx context.Context, userID UserID) error
	DeleteExpiredRefreshTokens(ctx context.Context) error
}
