package handler

import (
	"net/http"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
)

type CookieManager struct {
	cfg *config.Config
}

func NewCookieManager(cfg *config.Config) *CookieManager {
	return &CookieManager{cfg: cfg}
}

// Путь считается от внешнего (гейтвейного) адреса сервиса и должен
// покрывать и /refresh, и /logout.
func (cm *CookieManager) refreshTokenPath() string {
	return cm.cfg.JWT.CookiePathPrefix + "/v1/auth"
}

func (cm *CookieManager) SetTokenCookies(w http.ResponseWriter, tokens *user.TokenResponse) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    tokens.AccessToken,
		HttpOnly: true,
		Secure:   cm.cfg.JWT.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   int(tokens.ExpiresIn),
		Domain:   cm.cfg.JWT.CookieDomain,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    tokens.RefreshToken,
		HttpOnly: true,
		Secure:   cm.cfg.JWT.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     cm.refreshTokenPath(),
		MaxAge:   int(cm.cfg.JWT.RefreshTokenTTL.Seconds()),
		Domain:   cm.cfg.JWT.CookieDomain,
	})
}

func (cm *CookieManager) ClearTokenCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		HttpOnly: true,
		Secure:   cm.cfg.JWT.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
		MaxAge:   -1,
		Domain:   cm.cfg.JWT.CookieDomain,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		HttpOnly: true,
		Secure:   cm.cfg.JWT.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     cm.refreshTokenPath(),
		MaxAge:   -1,
		Domain:   cm.cfg.JWT.CookieDomain,
	})
}
