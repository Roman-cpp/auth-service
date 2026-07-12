package handler

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/service"
	"github.com/krypton/auth-service/pkg/httputil"
)

type UserHandler struct {
	svc *service.UserService
}

func NewUserHandler(svc *service.UserService) *UserHandler {
	return &UserHandler{svc: svc}
}

// requireSelf: пока в сервисе нет ролей, доступ к /users/{id} разрешён
// только владельцу аккаунта; администрирование чужих пользователей —
// задача будущего /admin API.
func requireSelf(w http.ResponseWriter, r *http.Request) (user.UserID, bool) {
	id := chi.URLParam(r, "id")
	authID, ok := r.Context().Value(middleware.ContextKeyUserID).(string)
	if !ok || authID != id {
		httputil.WriteJSON(w, http.StatusForbidden, httputil.ErrorResponse{Code: "forbidden", Message: "access denied"})
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
	if errors.Is(err, user.ErrNotFound) {
		httputil.WriteJSON(w, http.StatusNotFound, httputil.ErrorResponse{Code: "not_found", Message: "user not found"})
		return
	}
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: user.UserPreview{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}})
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := requireSelf(w, r)
	if !ok {
		return
	}

	err := h.svc.DeleteUser(r.Context(), id)
	if errors.Is(err, user.ErrNotFound) {
		httputil.WriteJSON(w, http.StatusNotFound, httputil.ErrorResponse{Code: "not_found", Message: "user not found"})
		return
	}
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
