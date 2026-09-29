package handler

import (
	"net/http"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
)

const (
	accessTokenCookie  = "access_token"
	refreshTokenCookie = "refresh_token"
	mfaTokenCookie     = "mfa_token"
	qrLoginCookie      = "qr_login"
)

type CookieManager struct {
	cfg *config.Config
}

func NewCookieManager(cfg *config.Config) *CookieManager {
	return &CookieManager{cfg: cfg}
}

// Пути считаются от внешнего (гейтвейного) адреса сервиса: nginx публикует
// /api/auth/v1/** и переписывает в /api/v1/**, а куки живут в браузере.
func (cm *CookieManager) refreshTokenPath() string {
	return cm.cfg.JWT.CookiePathPrefix + "/v1/auth"
}

// MFA-кука уже refresh-куки: она нужна ровно двум эндпоинтам второго шага
// и не должна уезжать вместе с каждым запросом к /auth.
func (cm *CookieManager) mfaTokenPath() string {
	return cm.cfg.JWT.CookiePathPrefix + "/v1/auth/mfa"
}

func (cm *CookieManager) cookie(name, value, path string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		HttpOnly: true,
		Secure:   cm.cfg.JWT.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		Path:     path,
		MaxAge:   maxAge,
		Domain:   cm.cfg.JWT.CookieDomain,
	}
}

func (cm *CookieManager) SetSessionCookies(w http.ResponseWriter, tokens *auth.TokenResponse) {
	http.SetCookie(w, cm.cookie(accessTokenCookie, tokens.AccessToken, "/", int(tokens.ExpiresIn)))
	http.SetCookie(w, cm.cookie(refreshTokenCookie, tokens.RefreshToken, cm.refreshTokenPath(),
		int(cm.cfg.JWT.RefreshTokenTTL.Seconds())))
	// Сессия открыта — промежуточные куки второго шага и QR-входа больше
	// не нужны.
	cm.ClearMFACookie(w)
	cm.ClearQRCookie(w)
}

func (cm *CookieManager) ClearSessionCookies(w http.ResponseWriter) {
	http.SetCookie(w, cm.cookie(accessTokenCookie, "", "/", -1))
	http.SetCookie(w, cm.cookie(refreshTokenCookie, "", cm.refreshTokenPath(), -1))
	cm.ClearMFACookie(w)
}

// SetMFACookie кладёт токен первого шага в httpOnly-куку, а не отдаёт его
// в теле: в JS он не нужен, а так его не достанет XSS.
func (cm *CookieManager) SetMFACookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, cm.cookie(mfaTokenCookie, token, cm.mfaTokenPath(),
		int(cm.cfg.JWT.MFATokenTTL.Seconds())))
}

func (cm *CookieManager) ClearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, cm.cookie(mfaTokenCookie, "", cm.mfaTokenPath(), -1))
}

// QR-кука нужна только компьютеру, ждущему подтверждения, — и только
// эндпоинтам /auth/qr.
func (cm *CookieManager) qrLoginPath() string {
	return cm.cfg.JWT.CookiePathPrefix + "/v1/auth/qr"
}

// SetQRCookie хранит секрет заявки на вход по QR. В теле ответа его нет по
// той же причине, что и MFA-токена: JS он не нужен, а XSS его не достанет.
func (cm *CookieManager) SetQRCookie(w http.ResponseWriter, secret string, expiresAt time.Time) {
	http.SetCookie(w, cm.cookie(qrLoginCookie, secret, cm.qrLoginPath(),
		int(time.Until(expiresAt).Seconds())))
}

func (cm *CookieManager) ClearQRCookie(w http.ResponseWriter) {
	http.SetCookie(w, cm.cookie(qrLoginCookie, "", cm.qrLoginPath(), -1))
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
