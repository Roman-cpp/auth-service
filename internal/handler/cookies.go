package handler

import (
	"net/http"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/user"
)

const refreshTokenPath = "/api/auth/v1/auth/refresh"

type CookieManager struct {
	cfg *config.Config
}

func NewCookieManager(cfg *config.Config) *CookieManager {
	return &CookieManager{cfg: cfg}
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
		Path:     refreshTokenPath,
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
		Path:     refreshTokenPath,
		MaxAge:   -1,
		Domain:   cm.cfg.JWT.CookieDomain,
	})
}
