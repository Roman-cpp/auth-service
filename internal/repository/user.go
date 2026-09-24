package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/domain/user"
)

// Набор колонок пользователя перечислен один раз: раньше три запроса
// дублировали список руками, и каждое новое поле приходилось дописывать
// в три места.
const userColumns = `id, email, password_hash, last_name, first_name, patronymic,
	email_verified_at, two_factor_enabled, role, must_change_password, created_by,
	token_version, deleted_at, created_at, updated_at`

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (*user.User, error) {
	u := &user.User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.LastName, &u.FirstName, &u.Patronymic,
		&u.EmailVerifiedAt, &u.TwoFactorEnabled, &u.Role, &u.MustChangePassword, &u.CreatedBy,
		&u.TokenVersion, &u.DeletedAt, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, user.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

// Upsert: повторная регистрация на ещё не подтверждённый адрес перезаписывает
// заявку вместо 409. Иначе любой мог бы занять чужой email навсегда — просто
// начав регистрацию и не подтвердив её. Подтверждённый аккаунт защищён
// условием в DO UPDATE: конфликт по нему не даёт ни одной строки, что и
// означает ErrEmailTaken.
//
// Арбитром конфликта служит частичный индекс idx_users_email_active, поэтому
// ON CONFLICT повторяет его предикат. Удалённые строки в него не входят —
// на освобождённый адрес регистрация просто заводит новый аккаунт, а старый
// остаётся восстановимым, пока его не займёт новый владелец.
//
// Той же дорогой идёт и заведение аккаунта модератором: неподтверждённая
// заявка на этот адрес перезаписывается целиком, вместе с ролью и флагами.
func (r *UserRepository) Upsert(ctx context.Context, dto user.CreateDTO) (*user.User, error) {
	role := dto.Role
	if role == "" {
		role = user.RoleUser
	}
	u, err := scanUser(r.pool.QueryRow(ctx,
		`INSERT INTO users (last_name, first_name, patronymic, email, password_hash,
		                    role, email_verified_at, must_change_password, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, CASE WHEN $7::bool THEN NOW() END, $8, $9)
		 ON CONFLICT (email) WHERE deleted_at IS NULL DO UPDATE
		    SET last_name            = EXCLUDED.last_name,
		        first_name           = EXCLUDED.first_name,
		        patronymic           = EXCLUDED.patronymic,
		        password_hash        = EXCLUDED.password_hash,
		        role                 = EXCLUDED.role,
		        email_verified_at    = EXCLUDED.email_verified_at,
		        must_change_password = EXCLUDED.must_change_password,
		        created_by           = EXCLUDED.created_by,
		        updated_at           = NOW()
		  WHERE users.email_verified_at IS NULL AND users.deleted_at IS NULL
		 RETURNING `+userColumns,
		dto.LastName, dto.FirstName, dto.Patronymic, dto.Email, dto.PasswordHash,
		role, dto.EmailVerified, dto.MustChangePassword, dto.CreatedBy,
	))
	if errors.Is(err, user.ErrNotFound) || isPgUniqueViolation(err) {
		return nil, user.ErrEmailTaken
	}
	return u, err
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*user.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE email = $1 AND deleted_at IS NULL`,
		email,
	))
}

func (r *UserRepository) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1 AND deleted_at IS NULL`,
		id,
	))
}

func (r *UserRepository) GetDeletedByEmail(ctx context.Context, email string) (*user.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users
		  WHERE email = $1 AND deleted_at IS NOT NULL
		  ORDER BY deleted_at DESC
		  LIMIT 1`,
		email,
	))
}

// SoftDelete отдаёт deleted_at обратно: окно восстановления отсчитывается от
// момента, зафиксированного базой, а не от времени на стороне приложения.
func (r *UserRepository) SoftDelete(ctx context.Context, id user.UserID) (time.Time, error) {
	var deletedAt time.Time
	err := r.pool.QueryRow(ctx,
		`UPDATE users SET deleted_at = NOW(), updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL
		  RETURNING deleted_at`, id,
	).Scan(&deletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, user.ErrNotFound
	}
	return deletedAt, err
}

// Restore возвращает аккаунт в строй. Занятость адреса не проверяется
// отдельным SELECT: между проверкой и UPDATE адрес успел бы занять кто-то
// ещё, поэтому решает уникальный индекс — конфликт с живым аккаунтом
// приходит как ErrEmailTaken.
//
// Незавершённая чужая регистрация на этот адрес при этом сносится: она не
// доказывает ничего (почта не подтверждена), а восстанавливающий предъявил
// пароль. Это то же правило, по которому Upsert перезаписывает
// неподтверждённую заявку, — иначе восстановление блокируется навсегда любым,
// кто начал регистрацию на чужой адрес.
func (r *UserRepository) Restore(ctx context.Context, id user.UserID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`DELETE FROM users living
		  USING users deleted
		  WHERE deleted.id = $1
		    AND living.email = deleted.email
		    AND living.deleted_at IS NULL
		    AND living.email_verified_at IS NULL`, id,
	); err != nil {
		return err
	}

	tag, err := tx.Exec(ctx,
		`UPDATE users SET deleted_at = NULL, updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NOT NULL`, id)
	if isPgUniqueViolation(err) {
		return user.ErrEmailTaken
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return user.ErrNotFound
	}

	return tx.Commit(ctx)
}

func (r *UserRepository) PurgeDeletedUsers(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE deleted_at < $1`, before)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *UserRepository) MarkEmailVerified(ctx context.Context, id user.UserID) error {
	return execExpectingRow(ctx, r.pool,
		`UPDATE users SET email_verified_at = NOW(), updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL AND email_verified_at IS NULL`, id)
}

// UpdatePassword не проверяет email_verified_at: сброс пароля доступен
// только подтверждённому аккаунту, но решается это в сервисе — здесь важно
// лишь не воскресить удалённого пользователя.
func (r *UserRepository) UpdatePassword(ctx context.Context, id user.UserID, passwordHash string) error {
	return execExpectingRow(ctx, r.pool,
		`UPDATE users SET password_hash = $2, must_change_password = FALSE, updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL`, id, passwordHash)
}

// ListUsers ищет подстрокой по email и ФИО. Спецсимволы LIKE в запросе
// экранируются: иначе «%» или «_» от модератора работали бы как шаблон.
func (r *UserRepository) ListUsers(ctx context.Context, f user.ListUsersFilter) ([]*user.User, int, error) {
	pattern := "%" + likeEscaper.Replace(f.Query) + "%"
	// Пустой запрос даёт шаблон «%%» — он совпадает со всеми строками.
	const where = `deleted_at IS NULL AND (email ILIKE $1 OR
		concat_ws(' ', last_name, first_name, patronymic) ILIKE $1)`

	var total int
	if err := r.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE `+where, pattern).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := r.pool.Query(ctx,
		`SELECT `+userColumns+` FROM users WHERE `+where+`
		  ORDER BY created_at DESC, id
		  LIMIT $2 OFFSET $3`,
		pattern, f.Limit, f.Offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	users := make([]*user.User, 0, f.Limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, u)
	}
	return users, total, rows.Err()
}

func (r *UserRepository) PromoteModerators(ctx context.Context, emails []string) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET role = 'moderator', updated_at = NOW()
		  WHERE email = ANY($1) AND deleted_at IS NULL AND role <> 'moderator'`, emails)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *UserRepository) SetTwoFactorEnabled(ctx context.Context, id user.UserID, enabled bool) error {
	return execExpectingRow(ctx, r.pool,
		`UPDATE users SET two_factor_enabled = $2, updated_at = NOW()
		  WHERE id = $1 AND deleted_at IS NULL AND two_factor_enabled <> $2`, id, enabled)
}

// ---- helpers ----

// execExpectingRow превращает «запрос не задел ни одной строки» в ErrNotFound.
// Все UPDATE выше несут в WHERE ещё и условие состояния (не удалён, не
// погашен, не отозван), поэтому ноль строк — это и «нет записи», и «состояние
// уже изменил кто-то другой»; для вызывающего это одно и то же.
func execExpectingRow(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) error {
	tag, err := pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return user.ErrNotFound
	}
	return nil
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}
