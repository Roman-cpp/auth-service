package middleware

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/pkg/httputil"
)

// RoleChecker — ровно то, что middleware нужно знать про роль. Роль
// читается из базы на каждый запрос, а не из токена: снятая роль должна
// перестать действовать сразу.
type RoleChecker interface {
	IsModerator(ctx context.Context, id user.UserID) (bool, error)
}

// RequireModerator ставится после JWTAuth: личность берётся из контекста,
// который тот заполнил.
func RequireModerator(c RoleChecker, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := UserIDFrom(r.Context())
			if !ok {
				unauthorized(w, "требуется авторизация")
				return
			}

			allowed, err := c.IsModerator(r.Context(), id)
			if err != nil {
				log.ErrorContext(r.Context(), "role check failed", slog.Any("error", err))
				httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{
					Code:    "internal_error",
					Message: "внутренняя ошибка сервера",
				})
				return
			}
			if !allowed {
				httputil.WriteJSON(w, http.StatusForbidden, httputil.ErrorResponse{
					Code:    "forbidden",
					Message: "недостаточно прав",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
