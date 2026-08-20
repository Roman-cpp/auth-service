package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/service"
	"github.com/krypton/auth-service/pkg/httputil"
)

type RegisterRequest struct {
	LastName   string  `json:"last_name"    validate:"required"`
	FirstName  string  `json:"first_name"    validate:"required"`
	Patronymic *string `json:"patronymic"    validate:""`
	Email      string  `json:"email"    validate:"required,email"`
	Password   string  `json:"password" validate:"required,min=8"`
}

var validate = validator.New()

type AuthHandler struct {
	svc     *service.AuthService
	cookies *CookieManager
}

func NewAuthHandler(svc *service.AuthService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{svc: svc, cookies: NewCookieManager(cfg)}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, httputil.ErrorResponse{Code: "bad_request", Message: err.Error()})
		return
	}
	if err := validate.Struct(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, httputil.ErrorResponse{Code: "bad_request", Message: err.Error()})
		return
	}

	dto := user.CreateDTO{
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		Patronymic: req.Patronymic,
		Email:      req.Email,
		Password:   req.Password,
	}

	u, err := h.svc.Register(r.Context(), &dto)
	if errors.Is(err, user.ErrEmailTaken) {
		httputil.WriteJSON(w, http.StatusConflict, httputil.ErrorResponse{Code: "email_taken", Message: "email already registered"})
		return
	}
	if err != nil {
		log.Printf("Register: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, httputil.Response{Data: u})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req user.Login
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, httputil.ErrorResponse{Code: "bad_request", Message: err.Error()})
		return
	}
	if err := validate.Struct(&req); err != nil {
		httputil.WriteJSON(w, http.StatusBadRequest, httputil.ErrorResponse{Code: "bad_request", Message: err.Error()})
		return
	}

	tokens, u, err := h.svc.Login(r.Context(), &req)
	if errors.Is(err, service.ErrInvalidCredentials) {
		httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{Code: "invalid_credentials", Message: "invalid email or password"})
		return
	}
	if err != nil {
		log.Printf("Login: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	h.cookies.SetTokenCookies(w, tokens)
	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: map[string]any{
		"user":          u,
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	}})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := extractRefreshToken(r)
	if refreshToken == "" {
		httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{Code: "unauthorized", Message: "refresh token not found"})
		return
	}

	tokens, err := h.svc.Refresh(r.Context(), &user.Refresh{RefreshToken: refreshToken})
	if errors.Is(err, service.ErrInvalidToken) {
		httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{Code: "invalid_token", Message: "invalid or expired refresh token"})
		return
	}
	if err != nil {
		log.Printf("Refresh: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	h.cookies.SetTokenCookies(w, tokens)
	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: map[string]any{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	}})
}

// extractRefreshToken resolves the refresh token from, in order of priority:
// the refresh_token cookie, the X-Refresh-Token header, or an
// "Authorization: Bearer <token>" header — letting non-cookie clients refresh.
func extractRefreshToken(r *http.Request) string {
	if cookie, err := r.Cookie("refresh_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	if header := r.Header.Get("X-Refresh-Token"); header != "" {
		return strings.TrimSpace(header)
	}
	if header := r.Header.Get("Authorization"); header != "" {
		if parts := strings.SplitN(header, " ", 2); len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if refreshToken := extractRefreshToken(r); refreshToken != "" {
		if err := h.svc.Logout(r.Context(), refreshToken); err != nil {
			log.Printf("Logout: %v", err)
		}
	}

	h.cookies.ClearTokenCookies(w)
	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: map[string]string{"message": "logged out successfully"}})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value(middleware.ContextKeyUserID).(string)
	if !ok {
		httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{Code: "unauthorized", Message: "unauthorized"})
		return
	}

	u, err := h.svc.GetByID(r.Context(), userID)
	if errors.Is(err, user.ErrNotFound) {
		httputil.WriteJSON(w, http.StatusUnauthorized, httputil.ErrorResponse{Code: "not_found", Message: "user not found"})
		return
	}
	if err != nil {
		log.Printf("Me: %v", err)
		httputil.WriteJSON(w, http.StatusInternalServerError, httputil.ErrorResponse{Code: "internal_error", Message: "internal server error"})
		return
	}

	httputil.WriteJSON(w, http.StatusOK, httputil.Response{Data: map[string]any{"user": user.UserPreview{ID: u.ID, Email: u.Email, CreatedAt: u.CreatedAt}}})
}

