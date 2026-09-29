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

	// Заявки на вход по QR-коду. Каждый переход статуса — условный UPDATE:
	// если заявка не в ожидаемом состоянии или протухла, возвращается
	// user.ErrNotFound, и параллельные запросы срабатывают ровно один раз.
	CreateQRLogin(ctx context.Context, secretHash, ip, userAgent string, expiresAt time.Time) (*QRLogin, error)
	GetQRLogin(ctx context.Context, id string) (*QRLogin, error)
	GetQRLoginBySecret(ctx context.Context, secretHash string) (*QRLogin, error)
	// ScanQRLogin закрепляет заявку за userID. Повторное сканирование тем же
	// пользователем проходит (перезагрузка страницы), другим — нет.
	ScanQRLogin(ctx context.Context, id string, userID user.UserID) (*QRLogin, error)
	// ApproveQRLogin продлевает срок до completeBy: компьютер должен успеть
	// забрать сессию, даже если подтвердили в последнюю секунду.
	ApproveQRLogin(ctx context.Context, id string, userID user.UserID, completeBy time.Time) error
	RejectQRLogin(ctx context.Context, id string, userID user.UserID) error
	// ConsumeQRLogin гасит подтверждённую заявку и возвращает, чья она.
	ConsumeQRLogin(ctx context.Context, secretHash string) (user.UserID, error)
	DeleteExpiredQRLogins(ctx context.Context) error
}
