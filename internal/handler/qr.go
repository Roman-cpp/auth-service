package handler

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	authctx "github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/internal/service/qrlogin"
)

// sseHeartbeat держит поток живым: без трафика nginx закрывает соединение
// через proxy_read_timeout (30s).
const sseHeartbeat = 15 * time.Second

type QRHandler struct {
	base
	svc     *qrlogin.Service
	cookies *CookieManager
}

func NewQRHandler(svc *qrlogin.Service, cfg *config.Config, log *slog.Logger) *QRHandler {
	return &QRHandler{
		base:    base{log: log},
		svc:     svc,
		cookies: NewCookieManager(cfg),
	}
}

// ---- компьютер ----

// Start заводит заявку. Секрет уходит в httpOnly-куку, в теле — только id
// для QR: ссылку на страницу подтверждения собирает фронтенд, ему известен
// собственный адрес.
func (h *QRHandler) Start(w http.ResponseWriter, r *http.Request) {
	start, err := h.svc.Start(r.Context(), clientIP(r), r.UserAgent())
	if err != nil {
		h.fail(w, r, "qr_start", err)
		return
	}

	h.cookies.SetQRCookie(w, start.Secret, start.ExpiresAt)
	writeData(w, r, http.StatusCreated, map[string]any{
		"id":         start.ID,
		"expires_at": start.ExpiresAt,
	})
}

// Events — поток статусов заявки (Server-Sent Events), ?id= — заявка, чей QR
// на экране. Каждое событие —
// `event: status` с `{"status": "..."}`; поток закрывается сервером, когда
// статус окончательный. На approved клиент вызывает Complete: куки сессии
// нельзя выставить посреди потока — заголовки уже отправлены.
func (h *QRHandler) Events(w http.ResponseWriter, r *http.Request) {
	secret := cookieValue(r, qrLoginCookie)
	if secret == "" {
		h.fail(w, r, "qr_events", auth.ErrQRLoginExpired)
		return
	}

	statuses, err := h.svc.Watch(r.Context(), r.URL.Query().Get("id"), secret)
	if err != nil {
		h.fail(w, r, "qr_events", err)
		return
	}

	// Поток живёт дольше WriteTimeout сервера (20s) — снимаем его для этого
	// запроса, но не насовсем: заявка всё равно истекает.
	rc := http.NewResponseController(w)
	if err := rc.SetWriteDeadline(time.Now().Add(h.svc.StreamLimit())); err != nil {
		h.log.ErrorContext(r.Context(), "qr_events: write deadline", slog.Any("error", err))
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	// nginx иначе буферизует ответ, и событие дойдёт до браузера только
	// вместе с концом потока.
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	heartbeat := time.NewTicker(sseHeartbeat)
	defer heartbeat.Stop()

	for {
		var chunk string
		select {
		case status, ok := <-statuses:
			if !ok {
				return
			}
			chunk = fmt.Sprintf("event: status\ndata: {\"status\":%q}\n\n", status)
		case <-heartbeat.C:
			chunk = ": ping\n\n"
		}

		if _, err := fmt.Fprint(w, chunk); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// Complete — последний шаг: подтверждённая заявка меняется на сессию.
func (h *QRHandler) Complete(w http.ResponseWriter, r *http.Request) {
	secret := cookieValue(r, qrLoginCookie)
	if secret == "" {
		h.fail(w, r, "qr_complete", auth.ErrQRLoginExpired)
		return
	}

	result, err := h.svc.Complete(r.Context(), secret)
	if err != nil {
		h.fail(w, r, "qr_complete", err)
		return
	}

	h.cookies.SetSessionCookies(w, result.Tokens)
	writeData(w, r, http.StatusOK, map[string]any{"user": result.User})
}

// ---- телефон ----

// Scan отдаёт, кто просит вход, — телефон показывает это перед кнопкой
// «Подтвердить».
func (h *QRHandler) Scan(w http.ResponseWriter, r *http.Request) {
	userID, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "qr_scan", auth.ErrInvalidToken)
		return
	}

	requester, err := h.svc.Scan(r.Context(), chi.URLParam(r, "id"), userID)
	if err != nil {
		h.fail(w, r, "qr_scan", err)
		return
	}

	writeData(w, r, http.StatusOK, map[string]any{"requester": requester})
}

func (h *QRHandler) Approve(w http.ResponseWriter, r *http.Request) {
	userID, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "qr_approve", auth.ErrInvalidToken)
		return
	}

	if err := h.svc.Approve(r.Context(), chi.URLParam(r, "id"), userID); err != nil {
		h.fail(w, r, "qr_approve", err)
		return
	}

	writeData(w, r, http.StatusOK, map[string]string{"message": "approved"})
}

func (h *QRHandler) Reject(w http.ResponseWriter, r *http.Request) {
	userID, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "qr_reject", auth.ErrInvalidToken)
		return
	}

	if err := h.svc.Reject(r.Context(), chi.URLParam(r, "id"), userID); err != nil {
		h.fail(w, r, "qr_reject", err)
		return
	}

	writeData(w, r, http.StatusOK, map[string]string{"message": "rejected"})
}

// clientIP: chimw.RealIP уже подставил X-Real-IP от гейтвея в RemoteAddr;
// без гейтвея там host:port.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
