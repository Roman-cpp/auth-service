package authz

import (
	"net/http"

	"github.com/krypton/auth-service/internal/domain/user"
	authctx "github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/internal/platform/httpx"
)

// RequireModerator пропускает только модераторов. Ставится после
// authn.JWTAuth: роль берётся из контекста, куда тот положил её из
// access-токена, — поэтому своего запроса в базу здесь нет.
func RequireModerator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := authctx.IdentityFrom(r.Context())
		if !ok {
			httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrorBody{
				Code:    "unauthorized",
				Message: "требуется авторизация",
			})
			return
		}
		if user.Role(id.Role) != user.RoleModerator {
			httpx.WriteError(w, r, http.StatusForbidden, httpx.ErrorBody{
				Code:    "forbidden",
				Message: "недостаточно прав",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
