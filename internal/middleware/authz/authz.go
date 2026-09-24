package authz

import (
	"net/http"

	"github.com/krypton/auth-service/internal/domain/user"
	authctx "github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/pkg/httputil"
)

// RequireRole пропускает только пользователей с указанной ролью. Ставится
// после authn.JWTAuth: роль берётся из контекста, куда тот положил её,
// прочитав пользователя из базы, — поэтому своего запроса здесь нет.
func RequireRole(role user.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := authctx.IdentityFrom(r.Context())
			if !ok {
				httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{
					Code:    "unauthorized",
					Message: "требуется авторизация",
				})
				return
			}
			if user.Role(id.Role) != role {
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
