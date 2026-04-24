package handler

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service"
)

type UserHandler struct {
	svc *service.UserService
}

func NewUserHandler(svc *service.UserService) *UserHandler {
	return &UserHandler{svc: svc}
}

func (h *UserHandler) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.svc.GetAll(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	resp := make([]user.UserResponse, 0, len(users))
	for _, u := range users {
		resp = append(resp, user.UserResponse{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt})
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *UserHandler) GetUserByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	u, err := h.svc.GetByID(r.Context(), id)
	if errors.Is(err, user.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, user.UserResponse{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt})
}

func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	err := h.svc.DeleteUser(r.Context(), id)
	if errors.Is(err, user.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal server error"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
