package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Маршруты собираются с nil-обработчиками: NewRouter их только регистрирует,
// а проверяется здесь сама таблица — chi разбирает шаблоны при регистрации
// и падает на конфликте, что без единого вызова роутера иначе не всплывёт.
func TestRouteTable(t *testing.T) {
	pass := func(next http.Handler) http.Handler { return next }
	r := NewRouter(Handlers{}, Middleware{Authn: pass, RequireModerator: pass})

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
		"POST /api/v1/auth/password/initial",
		"POST /api/v1/auth/account/restore",
		"GET /api/v1/auth/me",
		"GET /api/v1/auth/validate",
		"POST /api/v1/auth/qr/start",
		"GET /api/v1/auth/qr/events",
		"POST /api/v1/auth/qr/complete",
		"POST /api/v1/auth/qr/{id}/scan",
		"POST /api/v1/auth/qr/{id}/approve",
		"POST /api/v1/auth/qr/{id}/reject",
		"DELETE /api/v1/users/{id}",
		"GET /api/v1/admin/users",
		"POST /api/v1/admin/users",
		"DELETE /api/v1/admin/users/{id}",
		"POST /api/v1/admin/users/{id}/restore",
		"DELETE /api/v1/admin/users/{id}/permanent",
	}
	for _, route := range want {
		if !registered[route] {
			t.Errorf("route %q is not registered", route)
		}
	}
}

// Лимит считается по X-Real-IP от гейтвея. True-Client-IP и X-Forwarded-For
// приходят от клиента как есть: если бы роутер им верил, перебор
// обходил бы лимит, меняя заголовок в каждом запросе.
func TestLimitKeyIgnoresClientHeaders(t *testing.T) {
	pass := func(next http.Handler) http.Handler { return next }
	r := NewRouter(Handlers{}, Middleware{Authn: pass, RequireModerator: pass})

	register := func(realIP string, i int) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", nil)
		req.Header.Set("X-Real-IP", realIP)
		req.Header.Set("True-Client-IP", fmt.Sprintf("198.51.100.%d", i))
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	// registerLimiter — 5 в минуту.
	for i := range 5 {
		if code := register("203.0.113.7", i); code == http.StatusTooManyRequests {
			t.Fatalf("request %d limited too early", i+1)
		}
	}
	if code := register("203.0.113.7", 5); code != http.StatusTooManyRequests {
		t.Fatalf("6th request with rotated client headers: got %d, want 429", code)
	}
	if code := register("203.0.113.8", 6); code == http.StatusTooManyRequests {
		t.Fatalf("another X-Real-IP shares the bucket")
	}
}
