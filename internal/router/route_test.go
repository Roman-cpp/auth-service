package router

import (
	"net/http"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Маршруты собираются с nil-обработчиками: NewRouter их только регистрирует,
// а проверяется здесь сама таблица — chi разбирает шаблоны при регистрации
// и падает на конфликте, что без единого вызова роутера иначе не всплывёт.
func TestRouteTable(t *testing.T) {
	r := NewRouter(nil, nil, func(next http.Handler) http.Handler { return next })

	registered := map[string]bool{}
	err := chi.Walk(r.(chi.Routes), func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		registered[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}

	want := []string{
		"POST /api/v1/auth/register",
		"POST /api/v1/auth/verify-email",
		"POST /api/v1/auth/login",
		"POST /api/v1/auth/mfa/verify",
		"POST /api/v1/auth/password/forgot",
		"POST /api/v1/auth/password/reset",
		"POST /api/v1/auth/password/change",
		"POST /api/v1/auth/account/restore",
		"GET /api/v1/auth/me",
		"DELETE /api/v1/users/{id}",
	}
	for _, route := range want {
		if !registered[route] {
			t.Errorf("route %q is not registered", route)
		}
	}
}
