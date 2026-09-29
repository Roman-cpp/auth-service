// Package qrlogin — вход по QR-коду: компьютер без сессии показывает QR,
// телефон с открытой сессией сканирует его и подтверждает вход.
//
// Заявка проходит pending → scanned → approved → consumed. Каждое звено
// делает свой участник: компьютер заводит заявку и в конце забирает сессию,
// телефон сканирует и подтверждает (или отклоняет). Сессию выдаёт только
// предъявление секрета из httpOnly-куки компьютера — id из QR сам по себе
// не даёт ничего.
package qrlogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/token"
)

const (
	// completeWindow — сколько компьютер может забирать сессию после
	// подтверждения. Подтвердить могут в последнюю секунду жизни QR, и без
	// продления сессия пропала бы на ровном месте.
	completeWindow = time.Minute
	// pollInterval — как часто наблюдатель перечитывает заявку сам. Изменения
	// на этом же экземпляре приходят сразу через hub; таймер нужен для
	// изменений с других экземпляров и чтобы заметить истечение срока.
	pollInterval = 2 * time.Second
	// maxUserAgent: заголовок приходит от клиента, и хранить его целиком
	// незачем — на экране подтверждения нужно узнать браузер, не более.
	maxUserAgent = 512
)

type Service struct {
	repo   auth.Repository
	users  user.Repository
	tokens *token.Issuer
	cfg    config.QRLoginConfig
	hub    *hub
}

func NewService(repo auth.Repository, users user.Repository, tokens *token.Issuer, cfg config.QRLoginConfig) *Service {
	return &Service{repo: repo, users: users, tokens: tokens, cfg: cfg, hub: newHub()}
}

// StreamLimit — сколько самое большее может длиться наблюдение за заявкой:
// её жизнь плюс запас на последний опрос.
func (s *Service) StreamLimit() time.Duration {
	return s.cfg.TTL + 2*pollInterval
}

// ---- компьютер ----

// Start заводит заявку. Секрет возвращается один раз и дальше живёт только
// в куке компьютера; в базе — его SHA-256.
func (s *Service) Start(ctx context.Context, ip, userAgent string) (*auth.QRLoginStart, error) {
	secret, err := generateSecret()
	if err != nil {
		return nil, err
	}

	q, err := s.repo.CreateQRLogin(ctx, hashSecret(secret), ip, truncate(userAgent, maxUserAgent), time.Now().Add(s.cfg.TTL))
	if err != nil {
		return nil, err
	}
	return &auth.QRLoginStart{ID: q.ID, Secret: secret, ExpiresAt: q.ExpiresAt}, nil
}

// Watch отдаёт статусы заявки по мере их смены, начиная с текущего. Канал
// закрывается, когда статус стал окончательным или ctx отменён.
//
// Ошибка возвращается только если заявки нет уже на старте: дальше
// наблюдение идёт в фоне, и отвечать ошибкой после начала потока нечем.
//
// id — заявка, чей QR сейчас на экране. Кука у браузера одна на все вкладки
// и перезаписывается каждым start: если два start разошлись (вторая вкладка,
// двойной рендер), кука может оказаться от другой заявки, чем QR. Тогда
// честнее сразу сказать «устарел» — клиент заведёт новую, — чем следить не
// за той заявкой, которую сканируют.
func (s *Service) Watch(ctx context.Context, id, secret string) (<-chan auth.QRLoginStatus, error) {
	secretHash := hashSecret(secret)
	q, err := s.repo.GetQRLoginBySecret(ctx, secretHash)
	if errors.Is(err, user.ErrNotFound) {
		return nil, auth.ErrQRLoginExpired
	}
	if err == nil && q.ID != id {
		return nil, auth.ErrQRLoginExpired
	}
	if err != nil {
		return nil, err
	}

	wake, unsubscribe := s.hub.subscribe(q.ID)
	out := make(chan auth.QRLoginStatus, 1)

	go func() {
		defer close(out)
		defer unsubscribe()

		ticker := time.NewTicker(pollInterval)
		defer ticker.Stop()

		var last auth.QRLoginStatus
		for {
			status := q.VisibleStatus(time.Now())
			if status != last {
				select {
				case out <- status:
				case <-ctx.Done():
					return
				}
				last = status
			}
			if status.Final() {
				return
			}

			select {
			case <-ctx.Done():
				return
			case <-wake:
			case <-ticker.C:
			}

			fresh, err := s.repo.GetQRLoginBySecret(ctx, secretHash)
			switch {
			case errors.Is(err, user.ErrNotFound):
				// Уборщик успел удалить протухшую заявку.
				fresh = &auth.QRLogin{Status: auth.QRLoginConsumed}
			case err != nil:
				if ctx.Err() != nil {
					return
				}
				// Сбой чтения — не повод рвать поток: следующий тик
				// попробует снова, а срок заявки всё равно ограничен.
				slog.ErrorContext(ctx, "qr login: watch", slog.Any("error", err))
				continue
			}
			q = fresh
		}
	}()

	return out, nil
}

// Complete гасит подтверждённую заявку и открывает сессию.
//
// Второй фактор здесь не спрашивается: вход подтвердила сессия на телефоне,
// а она сама открывалась со всеми факторами. Потребовать код ещё раз —
// значит сделать QR-вход бессмысленным, не добавив защиты.
func (s *Service) Complete(ctx context.Context, secret string) (*auth.SessionResult, error) {
	secretHash := hashSecret(secret)
	userID, err := s.repo.ConsumeQRLogin(ctx, secretHash)
	if errors.Is(err, user.ErrNotFound) {
		return nil, s.explain(func() (*auth.QRLogin, error) {
			return s.repo.GetQRLoginBySecret(ctx, secretHash)
		})
	}
	if err != nil {
		return nil, err
	}

	u, err := s.users.GetByID(ctx, userID)
	if errors.Is(err, user.ErrNotFound) {
		// Аккаунт удалили между подтверждением и входом.
		return nil, auth.ErrQRLoginExpired
	}
	if err != nil {
		return nil, err
	}

	tokens, err := s.tokens.IssueSession(ctx, u)
	if err != nil {
		return nil, err
	}
	return &auth.SessionResult{User: user.NewUserPreview(u), Tokens: tokens}, nil
}

// ---- телефон ----

// Scan закрепляет заявку за вошедшим пользователем и возвращает, кто просит
// вход. Подтвердить её после этого может только он.
func (s *Service) Scan(ctx context.Context, id string, userID user.UserID) (*auth.QRLoginRequester, error) {
	q, err := s.repo.ScanQRLogin(ctx, id, userID)
	if errors.Is(err, user.ErrNotFound) {
		return nil, s.explain(func() (*auth.QRLogin, error) { return s.repo.GetQRLogin(ctx, id) })
	}
	if err != nil {
		return nil, err
	}

	s.hub.notify(q.ID)
	return &auth.QRLoginRequester{
		IP:        q.RequesterIP,
		UserAgent: q.RequesterUA,
		CreatedAt: q.CreatedAt,
		ExpiresAt: q.ExpiresAt,
	}, nil
}

// Approve разрешает компьютеру забрать сессию. Отдельный шаг после Scan,
// а не подтверждение самим сканированием: пользователь должен увидеть, чей
// компьютер просит вход, прежде чем пустить его.
func (s *Service) Approve(ctx context.Context, id string, userID user.UserID) error {
	err := s.repo.ApproveQRLogin(ctx, id, userID, time.Now().Add(completeWindow))
	if errors.Is(err, user.ErrNotFound) {
		return s.explain(func() (*auth.QRLogin, error) { return s.repo.GetQRLogin(ctx, id) })
	}
	if err != nil {
		return err
	}
	s.hub.notify(id)
	return nil
}

func (s *Service) Reject(ctx context.Context, id string, userID user.UserID) error {
	err := s.repo.RejectQRLogin(ctx, id, userID)
	if errors.Is(err, user.ErrNotFound) {
		return s.explain(func() (*auth.QRLogin, error) { return s.repo.GetQRLogin(ctx, id) })
	}
	if err != nil {
		return err
	}
	s.hub.notify(id)
	return nil
}

// ---- helpers ----

// explain разбирает, почему не сработал условный переход: заявка мертва
// (нужен новый QR) или жива, но не в том состоянии.
func (s *Service) explain(load func() (*auth.QRLogin, error)) error {
	q, err := load()
	if errors.Is(err, user.ErrNotFound) {
		return auth.ErrQRLoginExpired
	}
	if err != nil {
		return err
	}
	switch q.VisibleStatus(time.Now()) {
	case auth.QRLoginExpired, auth.QRLoginRejected:
		return auth.ErrQRLoginExpired
	default:
		return auth.ErrQRLoginState
	}
}

func generateSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashSecret: быстрый хеш по той же причине, что и у refresh-токенов
// (token.HashRefresh), — в секрете 256 бит энтропии.
func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// Обрезка по байтам может разрезать многобайтовый символ.
	return strings.ToValidUTF8(s[:max], "")
}
