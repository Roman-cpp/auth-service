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
	// GetByIDWithDeleted — то же, но и логически удалённый аккаунт: админке
	// нужно видеть его, чтобы восстановить или удалить навсегда.
	GetByIDWithDeleted(ctx context.Context, id UserID) (*User, error)
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
	// HardDelete физически удаляет один логически удалённый аккаунт, не
	// дожидаясь конца окна восстановления. Живой аккаунт не трогает —
	// ErrNotFound: удаление навсегда только вторым шагом.
	HardDelete(ctx context.Context, id UserID) error
	MarkEmailVerified(ctx context.Context, id UserID) error
	SetTwoFactorEnabled(ctx context.Context, id UserID, enabled bool) error
	// UpdatePassword заодно снимает MustChangePassword: любой пароль,
	// заданный самим владельцем, временным уже не является.
	UpdatePassword(ctx context.Context, id UserID, passwordHash string) error
	// ListUsers — аккаунты для админки и общее число подходящих под фильтр.
	// Живые — свежие сначала; удалённые (f.Deleted) — недавно удалённые сначала.
	ListUsers(ctx context.Context, f ListUsersFilter) ([]*User, int, error)
	// PromoteModerators выдаёт роль модератора живым аккаунтам с этими
	// адресами и возвращает, сколько строк изменилось.
	PromoteModerators(ctx context.Context, emails []string) (int64, error)
}
