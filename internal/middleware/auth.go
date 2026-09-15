package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/pkg/httputil"
)

type contextKey string

const (
	contextKeyUserID contextKey = "user_id"
	contextKeyEmail  contextKey = "email"
)

// TokenValidator — ровно то, что middleware нужно от сервиса. Зависимость
// на интерфейс, а не на *service.AuthService: так middleware тестируется
// без базы и не тянет за собой половину приложения.
type TokenValidator interface {
	ValidateAccessToken(token string) (*user.Claims, error)
}

func JWTAuth(v TokenValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)
			if token == "" {
				unauthorized(w, "требуется авторизация")
				return
			}

			// ValidateAccessToken отвергает MFA-токен первого шага:
			// он подписан тем же ключом, но имеет другой тип.
			claims, err := v.ValidateAccessToken(token)
			if err != nil {
				unauthorized(w, "сессия недействительна или истекла")
				return
			}

			ctx := context.WithValue(r.Context(), contextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, contextKeyEmail, claims.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFrom и EmailFrom — единственный способ достать личность из контекста.
// Ключи не экспортируются, поэтому подложить их снаружи нельзя.
func UserIDFrom(ctx context.Context) (user.UserID, bool) {
	id, ok := ctx.Value(contextKeyUserID).(user.UserID)
	return id, ok
}

func EmailFrom(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(contextKeyEmail).(string)
	return email, ok
}

func unauthorized(w http.ResponseWriter, message string) {
	httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{
		Code:    "unauthorized",
		Message: message,
	})
}

func extractToken(r *http.Request) string {
	if cookie, err := r.Cookie("access_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return extractBearer(r)
}

func extractBearer(r *http.Request) string {
	header := r.Header.Get("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return parts[1]
	}
	return ""
}
