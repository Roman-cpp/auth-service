package auth

import (
	"context"
	"time"

	"github.com/krypton/auth-service/internal/domain/user"
)

// Repository — хранилище всего, что относится ко входу: одноразовые коды,
// refresh-токены и отзыв access-токенов. Сами пользователи — в user.Repository.
type Repository interface {
	// IssueAuthCode гасит предыдущий живой код той же пары
	// (пользователь, назначение) и записывает новый.
	IssueAuthCode(ctx context.Context, userID user.UserID, purpose CodePurpose, codeHash string, expiresAt time.Time) (*AuthCode, error)
	// LatestAuthCode возвращает последний выданный код — в том числе уже
	// погашенный: по нему считается кулдаун на повторную отправку.
	LatestAuthCode(ctx context.Context, userID user.UserID, purpose CodePurpose) (*AuthCode, error)
	IncrementAuthCodeAttempts(ctx context.Context, id string) (int, error)
	// ConsumeAuthCode гасит код и возвращает user.ErrNotFound, если он уже был
	// погашен: так параллельная проверка одного кода срабатывает один раз.
	ConsumeAuthCode(ctx context.Context, id string) error
	DeleteExpiredAuthCodes(ctx context.Context) error

	SaveRefreshToken(ctx context.Context, userID user.UserID, tokenHash string, expiresAt time.Time) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	DeleteRefreshToken(ctx context.Context, tokenHash string) error
	DeleteAllRefreshTokens(ctx context.Context, userID user.UserID) error
	DeleteExpiredRefreshTokens(ctx context.Context) error

	// TokenRevocations — текущие версии токенов пользователей, у которых
	// недавно что-то отзывалось. Таблицу пополняет триггер в базе.
	TokenRevocations(ctx context.Context) (map[user.UserID]int64, error)
	// DeleteStaleTokenRevocations убирает записи старше before: все токены
	// со старыми версиями к этому моменту уже истекли сами.
	DeleteStaleTokenRevocations(ctx context.Context, before time.Time) error
}
