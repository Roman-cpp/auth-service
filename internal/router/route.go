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
// ограничение «не чаще письма в минуту на один аккаунт» живёт в CodeService,
// потому что httprate не умеет ключевать по телу запроса.
//
// KeyByRealIP: сервис стоит за gateway (nginx), который подставляет
// X-Real-IP; по RemoteAddr все клиенты слились бы в одну корзину.
func limit(requests int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.Limit(requests, window, httprate.WithKeyFuncs(httprate.KeyByRealIP))
}

func NewRouter(authH *handler.AuthHandler, userH *handler.UserHandler, authMw func(http.Handler) http.Handler) http.Handler {
	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
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
	)

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(registerLimiter).Post("/register", authH.Register)
			r.With(verifyLimiter).Post("/verify-email", authH.VerifyEmail)
			r.With(resendLimiter).Post("/resend-code", authH.ResendCode)
			r.With(loginLimiter).Post("/login", authH.Login)
			r.With(refreshLimiter).Post("/refresh", authH.Refresh)

			// Второй шаг входа. Личность берётся из mfa_token-куки,
			// поэтому authMw здесь неприменим — access-токена ещё нет.
			r.Route("/mfa", func(r chi.Router) {
				r.With(verifyLimiter).Post("/verify", authH.VerifyMFA)
				r.With(resendLimiter).Post("/resend", authH.ResendMFA)
			})

			r.Group(func(r chi.Router) {
				r.Use(authMw)
				r.Post("/logout", authH.Logout)
				// Без лимитера намеренно: в этот маршрут ходит auth_request
				// гейтвея на КАЖДЫЙ запрос к защищённым сервисам.
				r.Get("/me", authH.Me)

				r.Route("/2fa", func(r chi.Router) {
					r.With(resendLimiter).Post("/enable", authH.EnableTwoFactor)
					r.With(verifyLimiter).Post("/confirm", authH.ConfirmTwoFactor)
					r.With(loginLimiter).Post("/disable", authH.DisableTwoFactor)
				})
			})
		})

		// Листинг всех пользователей намеренно не выставлен:
		// он вернётся только вместе с админским RBAC.
		r.Route("/users", func(r chi.Router) {
			r.Use(authMw)
			r.Get("/{id}", userH.GetUserByID)
			r.Delete("/{id}", userH.DeleteUser)
		})
	})

	return r
}
