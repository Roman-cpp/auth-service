// Package mailer — доставка писем с кодами через mail-service. Сам
// auth-service ни шаблонов, ни SMTP не знает: он называет сценарий
// (auth.CodePurpose) и передаёт код, письмо собирает и отправляет почтовик.
package mailer

import (
	"context"
	"log/slog"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
)

// LogMailer печатает код в лог вместо отправки. Поддерживаемый режим
// `go run ./cmd/auth-service` без docker compose и почтовика; конфиг
// разрешает его только для SERVICE_ENV=local.
type LogMailer struct {
	log *slog.Logger
}

func NewLog(log *slog.Logger) *LogMailer {
	log.Warn("MAIL_TRANSPORT=log: confirmation codes will be written to the log instead of being sent")
	return &LogMailer{log: log}
}

func (m *LogMailer) SendCode(_ context.Context, to string, purpose auth.CodePurpose, code string, ttl time.Duration, _ string) error {
	m.log.Info("outgoing code (mail disabled)",
		slog.String("to", to),
		slog.String("purpose", string(purpose)),
		slog.String("code", code),
		slog.Duration("ttl", ttl),
	)
	return nil
}
