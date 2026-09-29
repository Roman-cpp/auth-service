package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/krypton/auth-service/internal/handler"
)

// Лимиты по IP. Защищают от перебора и от спама письмами с одного адреса;
// ограничение «не чаще письма в минуту на один аккаунт» живёт в otp.Service,
// потому что httprate не умеет ключевать по телу запроса.
//
// Ключ — IP клиента из handler.ClientIP (IPv6 — по /64, чтобы нельзя было
// перебирать адреса внутри своей подсети).
func limit(requests int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.LimitBy(requests, window, func(r *http.Request) (string, error) {
		return httprate.CanonicalizeIP(handler.ClientIP(r)), nil
	})
}

// Handlers — обработчики эндпоинтов по ресурсам.
type Handlers struct {
	Auth  *handler.AuthHandler
	User  *handler.UserHandler
	Admin *handler.AdminHandler
	QR    *handler.QRHandler
}

// Middleware — middleware доступа. Authn кладёт личность в контекст,
// RequireModerator читает её оттуда, поэтому ставится только после Authn.
type Middleware struct {
	Authn            func(http.Handler) http.Handler
	RequireModerator func(http.Handler) http.Handler
}

func NewRouter(h Handlers, mw Middleware) http.Handler {

	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	// Доверяем только X-Real-IP: gateway (nginx) перезаписывает его на каждом
	// запросе. chimw.RealIP сначала читал True-Client-IP, который nginx
	// пропускает от клиента как есть, — IP можно было подделать.
	r.Use(chimw.ClientIPFromHeader("X-Real-IP"))
	r.Use(chimw.Recoverer)

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name": "auth", "status":"ok"}`))
	})

	var (
		registerLimiter = limit(5, time.Minute)
		loginLimiter    = limit(10, time.Minute)
		// Ввод кода лимитирован мягче: у пользователя есть законные
		// опечатки, а жёсткий предел на попытки и так стоит в auth_codes.
		verifyLimiter  = limit(20, time.Minute)
		resendLimiter  = limit(5, time.Minute)
		refreshLimiter = limit(30, time.Minute)
		// Поток статусов QR-входа: один на экран входа, плюс переподключения
		// браузера и новые QR каждые пару минут.
		qrEventsLimiter = limit(30, time.Minute)
	)

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(registerLimiter).Post("/register", h.Auth.Register)
			r.With(verifyLimiter).Post("/verify-email", h.Auth.VerifyEmail)
			r.With(resendLimiter).Post("/resend-code", h.Auth.ResendCode)
			r.With(loginLimiter).Post("/login", h.Auth.Login)
			r.With(refreshLimiter).Post("/refresh", h.Auth.Refresh)

			// Восстановление удалённого аккаунта: сессии у владельца нет,
			// опознание по email и паролю — значит, поверхность для перебора
			// та же, что у входа, и лимит тот же.
			r.With(loginLimiter).Post("/account/restore", h.Auth.RestoreAccount)

			// Второй шаг входа. Личность берётся из mfa_token-куки,
			// поэтому authMw здесь неприменим — access-токена ещё нет.
			r.Route("/mfa", func(r chi.Router) {
				r.With(verifyLimiter).Post("/verify", h.Auth.VerifyMFA)
				r.With(resendLimiter).Post("/resend", h.Auth.ResendMFA)
			})

			// Вход по QR-коду. Компьютер без сессии опознаётся по qr_login-куке
			// (start, events, complete); телефон — по своей сессии.
			r.Route("/qr", func(r chi.Router) {
				r.With(loginLimiter).Post("/start", h.QR.Start)
				r.With(qrEventsLimiter).Get("/events", h.QR.Events)
				r.With(loginLimiter).Post("/complete", h.QR.Complete)

				r.Group(func(r chi.Router) {
					r.Use(mw.Authn, verifyLimiter)
					r.Post("/{id}/scan", h.QR.Scan)
					r.Post("/{id}/approve", h.QR.Approve)
					r.Post("/{id}/reject", h.QR.Reject)
				})
			})

			// Все три маршрута про пароль держатся вместе, хотя защищены
			// по-разному: forgot/reset доступны как раз тому, кто войти не
			// может, а change — только изнутри сессии.
			r.Route("/password", func(r chi.Router) {
				r.With(resendLimiter).Post("/forgot", h.Auth.ForgotPassword)
				r.With(verifyLimiter).Post("/reset", h.Auth.ResetPassword)
				// Замена временного пароля от модератора: сессии ещё нет,
				// опознание по email и паролю — лимит как у входа.
				r.With(loginLimiter).Post("/initial", h.Auth.ChangeInitialPassword)
				r.With(mw.Authn, loginLimiter).Post("/change", h.Auth.ChangePassword)
			})

			r.Group(func(r chi.Router) {
				r.Use(mw.Authn)
				r.Post("/logout", h.Auth.Logout)
				// Без лимитера намеренно: в /validate ходит auth_request
				// гейтвея на КАЖДЫЙ запрос к защищённым сервисам.
				r.Get("/validate", h.Auth.Validate)
				r.Get("/me", h.Auth.Me)

				r.Route("/2fa", func(r chi.Router) {
					r.With(resendLimiter).Post("/enable", h.Auth.EnableTwoFactor)
					r.With(verifyLimiter).Post("/confirm", h.Auth.ConfirmTwoFactor)
					r.With(loginLimiter).Post("/disable", h.Auth.DisableTwoFactor)
				})
			})
		})

		// Админка: только для модераторов. Роль проверяется после
		// аутентификации — moderatorMw берёт личность из контекста authMw.
		r.Route("/admin", func(r chi.Router) {
			r.Use(mw.Authn, mw.RequireModerator)
			r.Get("/users", h.Admin.ListUsers)
			r.Post("/users", h.Admin.CreateUser)
			// Удаление в два шага: сначала логическое (его можно отменить
			// restore), навсегда — только уже удалённого.
			r.Delete("/users/{id}", h.Admin.DeleteUser)
			r.Post("/users/{id}/restore", h.Admin.RestoreUser)
			r.Delete("/users/{id}/permanent", h.Admin.PurgeUser)
		})

		r.Route("/users", func(r chi.Router) {
			r.Use(mw.Authn)
			r.Get("/{id}", h.User.GetUserByID)
			r.Delete("/{id}", h.User.DeleteUser)
		})
	})

	return r
}
