package authn

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	authctx "github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/internal/platform/httpx"
)

// TokenValidator и RevocationChecker — ровно то, что middleware нужно от
// сервиса. Зависимость на интерфейсы, а не на конкретные типы: так middleware
// тестируется без базы и не тянет за собой половину приложения.
type TokenValidator interface {
	ValidateAccessToken(token string) (*auth.Claims, error)
}

type RevocationChecker interface {
	Check(id user.UserID, version int64) error
}

// JWTAuth проверяет access-токен и кладёт в контекст личность пользователя.
//
// В базу middleware не ходит: роль берётся из токена, а отзыв (смена роли,
// пароля, удаление аккаунта) проверяется по списку в памяти — токен с
// версией ниже текущей версии пользователя отвергается.
func JWTAuth(v TokenValidator, revocations RevocationChecker, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r)
			if token == "" {
				unauthorized(w, r, "требуется авторизация")
				return
			}

			// ValidateAccessToken отвергает MFA-токен первого шага:
			// он подписан тем же ключом, но имеет другой тип.
			claims, err := v.ValidateAccessToken(token)
			if err != nil {
				unauthorized(w, r, "сессия недействительна или истекла")
				return
			}

			switch err := revocations.Check(claims.UserID(), claims.TokenVersion); {
			case errors.Is(err, auth.ErrInvalidToken):
				// Отозван. 401, а не 403: клиент сделает refresh и получит
				// токен с актуальной ролью — или отказ, если аккаунта нет.
				unauthorized(w, r, "сессия недействительна или истекла")
				return
			case err != nil:
				log.ErrorContext(r.Context(), "authn: revocation check", slog.Any("error", err))
				httpx.WriteError(w, r, http.StatusServiceUnavailable, httpx.ErrorBody{
					Code:    "unavailable",
					Message: "сервис временно недоступен",
				})
				return
			}

			ctx := authctx.WithIdentity(r.Context(), authctx.Identity{
				UserID: claims.UserID(),
				Role:   string(claims.Role),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func unauthorized(w http.ResponseWriter, r *http.Request, message string) {
	httpx.WriteError(w, r, http.StatusUnauthorized, httpx.ErrorBody{
		Code:    "unauthorized",
		Message: message,
	})
}

// extractToken читает access-токен только из httpOnly-куки. Заголовок
// Authorization не принимается намеренно: токен в JS не попадает вовсе,
// и второго пути его предъявить быть не должно.
func extractToken(r *http.Request) string {
	if cookie, err := r.Cookie("access_token"); err == nil {
		return cookie.Value
	}
	return ""
}
