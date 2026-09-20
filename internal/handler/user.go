package handler

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/service"
)

type UserHandler struct {
	base
	svc     *service.UserService
	cookies *CookieManager
}

func NewUserHandler(svc *service.UserService, cfg *config.Config, log *slog.Logger) *UserHandler {
	return &UserHandler{base: base{log: log}, svc: svc, cookies: NewCookieManager(cfg)}
}

// requireSelf: пока в сервисе нет ролей, доступ к /users/{id} разрешён
// только владельцу аккаунта; администрирование чужих пользователей —
// задача будущего /admin API.
func requireSelf(w http.ResponseWriter, r *http.Request) (user.UserID, bool) {
	id := chi.URLParam(r, "id")
	authID, ok := middleware.UserIDFrom(r.Context())
	if !ok || authID != id {
		writeError(w, apiError{http.StatusForbidden, "forbidden", "доступ запрещён"})
		return "", false
	}
	return id, true
}

func (h *UserHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	id, ok := requireSelf(w, r)
	if !ok {
		return
	}

	u, err := h.svc.GetByID(r.Context(), id)
	if err != nil {
		h.fail(w, r, "get_user", err)
		return
	}

	writeData(w, http.StatusOK, user.NewUserPreview(u))
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := requireSelf(w, r)
	if !ok {
		return
	}

	restoreUntil, err := h.svc.DeleteUser(r.Context(), id)
	if err != nil {
		h.fail(w, r, "delete_user", err)
		return
	}

	// Сессию удалённого аккаунта гасим и на клиенте.
	h.cookies.ClearSessionCookies(w)
	// Не 204: срок, до которого аккаунт можно вернуть, клиенту нужно
	// показать сразу — другого места узнать его у пользователя нет.
	writeData(w, http.StatusOK, map[string]any{"restore_available_until": restoreUntil})
}
