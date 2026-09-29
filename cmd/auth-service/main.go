package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/handler"
	"github.com/krypton/auth-service/internal/mailer"
	"github.com/krypton/auth-service/internal/middleware/authn"
	"github.com/krypton/auth-service/internal/middleware/authz"
	"github.com/krypton/auth-service/internal/repository"
	"github.com/krypton/auth-service/internal/router"
	"github.com/krypton/auth-service/internal/service/admin"
	"github.com/krypton/auth-service/internal/service/auth"
	"github.com/krypton/auth-service/internal/service/otp"
	"github.com/krypton/auth-service/internal/service/qrlogin"
	"github.com/krypton/auth-service/internal/service/revocation"
	"github.com/krypton/auth-service/internal/service/token"
	"github.com/krypton/auth-service/internal/service/user"
)

const (
	shutdownTimeout = 10 * time.Second
	cleanupInterval = time.Hour
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", slog.Any("error", err))
		os.Exit(1)
	}
}

// run возвращает ошибку вместо log.Fatal: так отрабатывают все defer,
// в том числе закрытие пула соединений.
func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	log := newLogger(cfg.Service)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.Database.DSN)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return err
	}

	repo := repository.NewUserRepository(pool)
	sessions := repository.NewAuthRepository(pool)
	mail := mailer.New(mailer.NewSender(cfg.SMTP, log), cfg.SMTP.FromName)

	tokens := token.NewIssuer(sessions, cfg.JWT)
	codes := otp.NewService(sessions, mail, cfg.Codes)
	revocations := revocation.NewList(sessions)
	authSvc := auth.NewService(repo, sessions, tokens, codes, revocations, cfg.Account)
	userSvc := user.NewService(repo, sessions, revocations, cfg.Account)
	adminSvc := admin.NewService(repo, userSvc, cfg.Account)
	qrSvc := qrlogin.NewService(sessions, repo, tokens, cfg.QRLogin)

	// Не фатально: без этого сервис работает, просто без новых модераторов.
	if promoted, err := adminSvc.PromoteModerators(ctx, cfg.Account.ModeratorEmails); err != nil {
		log.Error("promote moderators", slog.Any("error", err))
	} else if promoted > 0 {
		log.Info("moderators promoted from MODERATOR_EMAILS", slog.Int64("count", promoted))
	}

	// Фатально: без списка отзыва authn не может честно проверить ни один
	// токен. Загружается после выдачи ролей, чтобы уже учесть её.
	if err := revocations.Sync(ctx); err != nil {
		return err
	}
	go revocations.Run(ctx, log)

	handlers := router.Handlers{
		Auth:  handler.NewAuthHandler(authSvc, cfg, log),
		User:  handler.NewUserHandler(userSvc, cfg, log),
		Admin: handler.NewAdminHandler(adminSvc, log),
		QR:    handler.NewQRHandler(qrSvc, cfg, log),
	}
	middleware := router.Middleware{
		Authn:            authn.JWTAuth(authSvc, revocations, log),
		RequireModerator: authz.RequireModerator,
	}

	go runCleanup(ctx, repo, sessions, cfg, log)

	srv := &http.Server{
		Addr:              ":" + cfg.Service.Port,
		Handler:           router.NewRouter(handlers, middleware),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Больше, чем у остальных сервисов: письмо с кодом отправляется
		// синхронно внутри запроса, и на это заложен SMTP_TIMEOUT.
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("server listening", slog.String("addr", srv.Addr), slog.Bool("smtp", cfg.SMTP.Enabled()))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	log.Info("server stopped")
	return nil
}

func newLogger(cfg config.ServiceConfig) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}

	// Локально читаемее текст, в контейнере логи собирает promtail → loki,
	// которому нужен JSON.
	var h slog.Handler
	if cfg.Env == "local" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(h).With(slog.String("service", cfg.Name))
}

// runCleanup убирает протухшие refresh-токены, одноразовые коды и заявки
// на вход по QR, а также аккаунты, у которых кончилось окно восстановления.
// Первые три таблицы растут при каждом входе, и без уборки чистятся только
// вручную.
func runCleanup(
	ctx context.Context,
	repo *repository.UserRepository,
	sessions *repository.AuthRepository,
	cfg *config.Config,
	log *slog.Logger,
) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sessions.DeleteExpiredRefreshTokens(ctx); err != nil {
				log.Error("cleanup refresh tokens", slog.Any("error", err))
			}
			if err := sessions.DeleteExpiredAuthCodes(ctx); err != nil {
				log.Error("cleanup auth codes", slog.Any("error", err))
			}
			if err := sessions.DeleteExpiredQRLogins(ctx); err != nil {
				log.Error("cleanup qr logins", slog.Any("error", err))
			}
			// Запись об отзыве нужна, пока жив хоть один токен со старой
			// версией, — не дольше TTL access-токена. Запас — на случай,
			// если TTL успели поднять, пока токены ещё живы.
			staleBefore := time.Now().Add(-2 * cfg.JWT.AccessTokenTTL)
			if err := sessions.DeleteStaleTokenRevocations(ctx, staleBefore); err != nil {
				log.Error("cleanup token revocations", slog.Any("error", err))
			}

			// Удаление аккаунта логическое: строка живёт, пока её можно
			// вернуть. Здесь она уходит окончательно, унося каскадом коды
			// и refresh-токены.
			purged, err := repo.PurgeDeletedUsers(ctx, time.Now().Add(-cfg.Account.RestoreWindow))
			if err != nil {
				log.Error("purge deleted users", slog.Any("error", err))
			}
			if purged > 0 {
				log.Info("purged deleted accounts", slog.Int64("count", purged))
			}
		}
	}
}
