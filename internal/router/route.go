package router

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/krypton/auth-service/internal/handler"
)

func NewRouter(r *chi.Mux, authH *handler.AuthHandler, userH *handler.UserHandler, authMw func(http.Handler) http.Handler) {

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name": "auth", "status":"ok"}`))
	})

	// Защита от перебора паролей и спама регистрациями.
	// KeyByRealIP: сервис стоит за gateway (nginx), который подставляет
	// X-Real-IP; по RemoteAddr все клиенты слились бы в одну корзину.
	loginLimiter := httprate.Limit(10, time.Minute, httprate.WithKeyFuncs(httprate.KeyByRealIP))
	registerLimiter := httprate.Limit(5, time.Minute, httprate.WithKeyFuncs(httprate.KeyByRealIP))
	refreshLimiter := httprate.Limit(30, time.Minute, httprate.WithKeyFuncs(httprate.KeyByRealIP))

	r.Route("/api/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.With(registerLimiter).Post("/register", authH.Register)
			r.With(loginLimiter).Post("/login", authH.Login)
			r.With(refreshLimiter).Post("/refresh", authH.Refresh)

			r.Group(func(r chi.Router) {
				r.Use(authMw)
				r.Post("/logout", authH.Logout)
				r.Get("/me", authH.Me)
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
}
