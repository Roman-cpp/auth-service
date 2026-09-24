package authn

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/pkg/httputil"
)

// TokenValidator и RevocationChecker — ровно то, что middleware нужно от
// сервиса. Зависимость на интерфейсы, а не на конкретные типы: так middleware
// тестируется без базы и не тянет за собой половину приложения.
type TokenValidator interface {
	ValidateAccessToken(token string) (*user.Claims, error)
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

			switch err := revocations.Check(claims.UserID(), claims.TokenVersion); {
			case errors.Is(err, user.ErrInvalidToken):
				// Отозван. 401, а не 403: клиент сделает refresh и получит
				// токен с актуальной ролью — или отказ, если аккаунта нет.
				unauthorized(w, "сессия недействительна или истекла")
				return
			case err != nil:
				log.ErrorContext(r.Context(), "authn: revocation check", slog.Any("error", err))
				httputil.WriteJSON(w, http.StatusServiceUnavailable, httputil.ErrorResponse{
					Code:    "unavailable",
					Message: "сервис временно недоступен",
				})
				return
			}

			ctx := auth.WithIdentity(r.Context(), auth.Identity{
				UserID: claims.UserID(),
				Role:   string(claims.Role),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func unauthorized(w http.ResponseWriter, message string) {
	httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{
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
