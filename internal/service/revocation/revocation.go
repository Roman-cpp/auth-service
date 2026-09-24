package revocation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
)

const (
	// SyncInterval — как часто подтягивать отзывы, сделанные мимо
	// этого экземпляра (другим экземпляром или вручную в базе). Это же —
	// предельная задержка их действия.
	SyncInterval = 5 * time.Second
	// maxStaleness: если список не обновлялся дольше, база, скорее
	// всего, недоступна, и отзыв, сделанный за это время, мог быть пропущен.
	// Тогда токены не принимаются вовсе — лучше отказать, чем пропустить
	// разжалованного модератора.
	maxStaleness = time.Minute
)

// Source — всё, что списку нужно от хранилища.
type Source interface {
	TokenRevocations(ctx context.Context) (map[user.UserID]int64, error)
}

// List — копия token_revocations в памяти. По ней каждый
// access-токен проверяется без запроса к базе: токен отозван, если его
// версия ниже текущей версии пользователя.
//
// Таблица маленькая (только пользователи с отзывом за последний TTL
// access-токена), поэтому синхронизация — полная перезагрузка, а не выборка
// изменений: так не теряются транзакции, закоммиченные позже своего NOW().
type List struct {
	repo Source
	now  func() time.Time

	mu       sync.RWMutex
	versions map[user.UserID]int64
	syncedAt time.Time
}

func NewList(repo Source) *List {
	return &List{repo: repo, now: time.Now, versions: map[user.UserID]int64{}}
}

// Sync перечитывает таблицу целиком. Вызывается по таймеру и сразу после
// операций этого экземпляра, которые отзывают токены, — чтобы они
// действовали немедленно, а не к следующему тику.
func (l *List) Sync(ctx context.Context) error {
	versions, err := l.repo.TokenRevocations(ctx)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.versions = versions
	l.syncedAt = l.now()
	l.mu.Unlock()
	return nil
}

// Check возвращает ErrInvalidToken для отозванного токена и
// ErrRevocationsStale, если список слишком давно не обновлялся.
func (l *List) Check(id user.UserID, version int64) error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if l.now().Sub(l.syncedAt) > maxStaleness {
		return auth.ErrRevocationsStale
	}
	if current, ok := l.versions[id]; ok && version < current {
		return auth.ErrInvalidToken
	}
	return nil
}

// Run держит список свежим до отмены ctx. Ошибка синхронизации не роняет
// сервис: старый список продолжает действовать, пока не устареет.
func (l *List) Run(ctx context.Context, log *slog.Logger) {
	ticker := time.NewTicker(SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := l.Sync(ctx); err != nil {
				log.Error("sync token revocations", slog.Any("error", err))
			}
		}
	}
}
