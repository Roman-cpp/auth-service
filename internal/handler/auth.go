package handler

import (
	"log/slog"
	"net/http"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/service"
)

type AuthHandler struct {
	base
	svc     *service.AuthService
	cookies *CookieManager
}

func NewAuthHandler(svc *service.AuthService, cfg *config.Config, log *slog.Logger) *AuthHandler {
	return &AuthHandler{
		base:    base{log: log},
		svc:     svc,
		cookies: NewCookieManager(cfg),
	}
}

// Register — первый шаг регистрации: аккаунт заведён, код ушёл на почту,
// сессии нет. Куки здесь намеренно не выставляются.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.Register](w, r)
	if !ok {
		return
	}

	result, err := h.svc.Register(r.Context(), req)
	if err != nil {
		h.fail(w, r, "register", err)
		return
	}

	writeData(w, http.StatusCreated, map[string]any{
		"user":         result.User,
		"verification": result.Challenge,
	})
}

// VerifyEmail — второй шаг регистрации. Успех сразу открывает сессию.
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.VerifyCode](w, r)
	if !ok {
		return
	}

	result, err := h.svc.VerifyEmail(r.Context(), req)
	if err != nil {
		h.fail(w, r, "verify_email", err)
		return
	}

	h.cookies.SetSessionCookies(w, result.Tokens)
	writeData(w, http.StatusOK, map[string]any{"user": result.User})
}

// ResendCode отвечает одинаково для известного и неизвестного адреса —
// иначе эндпоинт превращается в проверку «есть ли такой аккаунт».
func (h *AuthHandler) ResendCode(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.ResendCode](w, r)
	if !ok {
		return
	}

	challenge, err := h.svc.ResendEmailVerification(r.Context(), req.Email)
	if err != nil {
		h.fail(w, r, "resend_code", err)
		return
	}

	writeData(w, http.StatusAccepted, map[string]any{"verification": challenge})
}

// Login отвечает одной из двух форм: либо сессия открыта, либо требуется
// второй фактор. Во втором случае в ответе нет данных пользователя — до
// ввода кода раскрывать их нечего.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.Login](w, r)
	if !ok {
		return
	}

	result, err := h.svc.Login(r.Context(), req)
	if err != nil {
		h.fail(w, r, "login", err)
		return
	}

	if result.MFARequired() {
		h.cookies.SetMFACookie(w, result.MFAToken)
		writeData(w, http.StatusOK, map[string]any{
			"mfa_required": true,
			"verification": result.Challenge,
		})
		return
	}

	h.cookies.SetSessionCookies(w, result.Tokens)
	writeData(w, http.StatusOK, map[string]any{
		"mfa_required": false,
		"user":         result.User,
	})
}

func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	token := cookieValue(r, mfaTokenCookie)
	if token == "" {
		h.fail(w, r, "verify_mfa", user.ErrInvalidToken)
		return
	}

	req, ok := decodeJSON[user.MFAVerify](w, r)
	if !ok {
		return
	}

	result, err := h.svc.VerifyMFA(r.Context(), token, req.Code)
	if err != nil {
		h.fail(w, r, "verify_mfa", err)
		return
	}

	h.cookies.SetSessionCookies(w, result.Tokens)
	writeData(w, http.StatusOK, map[string]any{"user": result.User})
}

func (h *AuthHandler) ResendMFA(w http.ResponseWriter, r *http.Request) {
	token := cookieValue(r, mfaTokenCookie)
	if token == "" {
		h.fail(w, r, "resend_mfa", user.ErrInvalidToken)
		return
	}

	refreshed, challenge, err := h.svc.ResendMFACode(r.Context(), token)
	if err != nil {
		h.fail(w, r, "resend_mfa", err)
		return
	}

	// Окно на ввод кода продлевается вместе с самим кодом.
	h.cookies.SetMFACookie(w, refreshed)
	writeData(w, http.StatusAccepted, map[string]any{"verification": challenge})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	token := cookieValue(r, refreshTokenCookie)
	if token == "" {
		h.fail(w, r, "refresh", user.ErrInvalidToken)
		return
	}

	tokens, err := h.svc.Refresh(r.Context(), token)
	if err != nil {
		h.fail(w, r, "refresh", err)
		return
	}

	h.cookies.SetSessionCookies(w, tokens)
	writeData(w, http.StatusOK, map[string]string{"message": "ok"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if token := cookieValue(r, refreshTokenCookie); token != "" {
		if err := h.svc.Logout(r.Context(), token); err != nil {
			// Сессию всё равно закрываем на клиенте: куки чистятся ниже.
			h.log.ErrorContext(r.Context(), "logout", slog.Any("error", err))
		}
	}

	h.cookies.ClearSessionCookies(w)
	writeData(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "me", user.ErrInvalidToken)
		return
	}

	u, err := h.svc.GetByID(r.Context(), userID)
	if err != nil {
		h.fail(w, r, "me", err)
		return
	}

	// gateway's auth_request reads this header to propagate the identity to downstream services
	w.Header().Set("X-User-Id", u.ID)
	writeData(w, http.StatusOK, map[string]any{"user": user.NewUserPreview(u)})
}

// RestoreAccount возвращает удалённый аккаунт владельцу. Сессию не открывает:
// после восстановления нужно войти обычным путём, со вторым фактором, если
// он включён.
func (h *AuthHandler) RestoreAccount(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.RestoreAccount](w, r)
	if !ok {
		return
	}

	u, err := h.svc.RestoreAccount(r.Context(), req.Email, req.Password)
	if err != nil {
		h.fail(w, r, "restore_account", err)
		return
	}

	writeData(w, http.StatusOK, map[string]any{"user": u})
}

// ---- пароль ----

// ForgotPassword отвечает одинаково для известного и неизвестного адреса —
// как и ResendCode, иначе эндпоинт превращается в проверку «есть ли аккаунт».
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.ForgotPassword](w, r)
	if !ok {
		return
	}

	challenge, err := h.svc.StartPasswordReset(r.Context(), req.Email)
	if err != nil {
		h.fail(w, r, "forgot_password", err)
		return
	}

	writeData(w, http.StatusAccepted, map[string]any{"verification": challenge})
}

// ResetPassword намеренно не открывает сессию: после смены пароля нужно
// войти заново — в том числе со вторым фактором, если он включён.
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeJSON[user.ResetPassword](w, r)
	if !ok {
		return
	}

	if err := h.svc.ResetPassword(r.Context(), req); err != nil {
		h.fail(w, r, "reset_password", err)
		return
	}

	// Refresh-токены отозваны все до одного, так что куки на этом клиенте
	// (если он всё же был залогинен) уже ничего не стоят.
	h.cookies.ClearSessionCookies(w)
	writeData(w, http.StatusOK, map[string]string{"message": "password changed"})
}

// ChangePassword выдаёт новую пару токенов: старая отозвана вместе со всеми
// остальными сессиями, и без замены текущий клиент разлогинился бы сам.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "change_password", user.ErrInvalidToken)
		return
	}
	req, ok := decodeJSON[user.ChangePassword](w, r)
	if !ok {
		return
	}

	result, err := h.svc.ChangePassword(r.Context(), userID, req)
	if err != nil {
		h.fail(w, r, "change_password", err)
		return
	}

	h.cookies.SetSessionCookies(w, result.Tokens)
	writeData(w, http.StatusOK, map[string]any{"user": result.User})
}

// ---- управление вторым фактором ----

func (h *AuthHandler) EnableTwoFactor(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "enable_2fa", user.ErrInvalidToken)
		return
	}
	req, ok := decodeJSON[user.PasswordConfirm](w, r)
	if !ok {
		return
	}

	challenge, err := h.svc.StartEnableTwoFactor(r.Context(), userID, req.Password)
	if err != nil {
		h.fail(w, r, "enable_2fa", err)
		return
	}

	writeData(w, http.StatusAccepted, map[string]any{"verification": challenge})
}

func (h *AuthHandler) ConfirmTwoFactor(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "confirm_2fa", user.ErrInvalidToken)
		return
	}
	req, ok := decodeJSON[user.MFAVerify](w, r)
	if !ok {
		return
	}

	u, err := h.svc.ConfirmEnableTwoFactor(r.Context(), userID, req.Code)
	if err != nil {
		h.fail(w, r, "confirm_2fa", err)
		return
	}

	writeData(w, http.StatusOK, map[string]any{"user": u})
}

func (h *AuthHandler) DisableTwoFactor(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "disable_2fa", user.ErrInvalidToken)
		return
	}
	req, ok := decodeJSON[user.PasswordConfirm](w, r)
	if !ok {
		return
	}

	u, err := h.svc.DisableTwoFactor(r.Context(), userID, req.Password)
	if err != nil {
		h.fail(w, r, "disable_2fa", err)
		return
	}

	writeData(w, http.StatusOK, map[string]any{"user": u})
}
