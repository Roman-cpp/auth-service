package auth

import (
	"time"

	"github.com/krypton/auth-service/internal/domain/user"
)

// QRLoginStatus — этап заявки на вход по QR-коду. Переходы только вперёд:
// pending → scanned → approved → consumed, либо scanned → rejected.
type QRLoginStatus string

const (
	QRLoginPending  QRLoginStatus = "pending"
	QRLoginScanned  QRLoginStatus = "scanned"
	QRLoginApproved QRLoginStatus = "approved"
	QRLoginRejected QRLoginStatus = "rejected"
	QRLoginConsumed QRLoginStatus = "consumed"
	// QRLoginExpired в базе не хранится: это pending/scanned/approved заявка,
	// у которой вышел срок. Клиенту отдаётся вместо них.
	QRLoginExpired QRLoginStatus = "expired"
)

type QRLogin struct {
	ID         string
	SecretHash string
	Status     QRLoginStatus
	// UserID — кто отсканировал; nil, пока заявка в pending.
	UserID      *user.UserID
	RequesterIP string
	RequesterUA string
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

func (q *QRLogin) Expired(now time.Time) bool {
	return now.After(q.ExpiresAt)
}

// VisibleStatus — статус, который видит компьютер: живая заявка с вышедшим
// сроком и уже погашенная для него одинаково мертвы.
func (q *QRLogin) VisibleStatus(now time.Time) QRLoginStatus {
	switch {
	case q.Status == QRLoginConsumed:
		return QRLoginExpired
	case q.Status == QRLoginRejected:
		return QRLoginRejected
	case q.Expired(now):
		return QRLoginExpired
	default:
		return q.Status
	}
}

// Final: дальше статус заявки уже не изменится, следить за ней незачем.
func (s QRLoginStatus) Final() bool {
	return s == QRLoginApproved || s == QRLoginRejected || s == QRLoginExpired || s == QRLoginConsumed
}

// QRLoginStart — то, что получает компьютер при заведении заявки. Secret
// уходит только в httpOnly-куку, в тело ответа — id и срок.
type QRLoginStart struct {
	ID        string
	Secret    string
	ExpiresAt time.Time
}

// QRLoginRequester — что показывается на телефоне перед подтверждением:
// по этим данным пользователь понимает, чей компьютер просит вход.
type QRLoginRequester struct {
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
