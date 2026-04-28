package router

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/krypton/auth-service/internal/handler"
)

func NewRouter(r *chi.Mux, authH *handler.AuthHandler, userH *handler.UserHandler, authMw func(http.Handler) http.Handler) {

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name": "auth", "status":"ok"}`))
	})

	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/register", authH.Register)
		r.Post("/login", authH.Login)
		r.Post("/refresh", authH.Refresh)

		r.Group(func(r chi.Router) {
			r.Use(authMw)
			r.Post("/logout", authH.Logout)
			r.Get("/me", authH.Me)
		})

		r.Route("/users", func(r chi.Router) {
			r.Use(authMw)
			r.Get("/", userH.GetUsers)
			r.Get("/{id}", userH.GetUserByID)
			r.Delete("/{id}", userH.DeleteUser)
		})
	})
}
