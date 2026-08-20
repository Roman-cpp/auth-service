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

// GetMe returns the authenticated user's own profile. The user id comes from
// the auth middleware, so there is no path parameter.
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.ContextKeyUserID).(string)
	if !ok {
		httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{Code: "unauthorized", Message: "unauthorized"})
		return
	}

	u, err := h.svc.GetByID(r.Context(), userID)
	if errors.Is(err, user.ErrNotFound) {
		httputil.WriteJSON(w, http.StatusNotFound, httputil.ErrorResponse{Code: "not_found", Message: "user not found"})
		return
	}
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: user.Profile{
		UserID:      u.ID,
		Email:       u.Email,
		Name:        u.DisplayName(),
		Role:        u.Role,
		Status:      u.Status,
		CreatedAt:   u.CreatedAt,
		LastLoginAt: u.LastLoginAt,
	}})
}

func (h *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.GetAll(r.Context())
	if err != nil {
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	resp := make([]user.UserPreview, 0, len(users))
	for _, u := range users {
		resp = append(resp, user.UserPreview{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt})
	}
	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: resp})
}

func (h *UserHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

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
	id := chi.URLParam(r, "id")

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
