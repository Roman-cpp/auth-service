// Package mailer отвечает за доставку транзакционных писем. Наружу торчит
// один интерфейс Sender, поэтому SMTP подменяется логом (локальный запуск)
// или мок-реализацией (тесты) без изменений в бизнес-логике.
package mailer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/krypton/auth-service/internal/config"
	mail "github.com/wneessen/go-mail"
)

type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// NewSender выбирает транспорт по конфигу: без SMTP_HOST сервис поднимается
// с LogSender. Это не заглушка «на всякий случай», а поддерживаемый режим
// `go run ./cmd/auth-service` без docker compose — иначе регистрацию
// невозможно довести до конца, не подняв почтовый сервер.
func NewSender(cfg config.SMTPConfig, log *slog.Logger) Sender {
	if !cfg.Enabled() {
		log.Warn("SMTP is not configured, confirmation codes will be written to the log")
		return &LogSender{log: log}
	}
	return &SMTPSender{cfg: cfg}
}

type SMTPSender struct {
	cfg config.SMTPConfig
}

func (s *SMTPSender) Send(ctx context.Context, msg Message) error {
	m := mail.NewMsg()
	if err := m.FromFormat(s.cfg.FromName, s.cfg.From); err != nil {
		return fmt.Errorf("set From: %w", err)
	}
	if err := m.To(msg.To); err != nil {
		return fmt.Errorf("set To: %w", err)
	}
	m.Subject(msg.Subject)
	// text/plain основной частью, text/html альтернативой: почтовики выбирают
	// последнюю понятную им часть, а клиенты без HTML остаются с читаемым текстом.
	m.SetBodyString(mail.TypeTextPlain, msg.Text)
	m.AddAlternativeString(mail.TypeTextHTML, msg.HTML)

	client, err := mail.NewClient(s.cfg.Host, s.clientOptions()...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("smtp send: %w", err)
	}
	return nil
}

func (s *SMTPSender) clientOptions() []mail.Option {
	opts := []mail.Option{
		mail.WithPort(s.cfg.Port),
		mail.WithTimeout(s.cfg.Timeout),
	}

	switch s.cfg.Transport {
	case config.SMTPTransportNone:
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	case config.SMTPTransportTLS:
		opts = append(opts, mail.WithSSL(), mail.WithTLSPolicy(mail.TLSMandatory))
	default:
		// TLSMandatory, а не Opportunistic: молчаливый откат в открытый
		// текст на проде означал бы отправку кодов входа в открытом виде.
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}

	if s.cfg.Username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover),
			mail.WithUsername(s.cfg.Username),
			mail.WithPassword(s.cfg.Password),
		)
	} else {
		// Mailpit и прочие локальные приёмники аутентификации не требуют;
		// без явного NoAuth go-mail попытается её согласовать и упадёт.
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthNoAuth))
	}

	return opts
}

// LogSender печатает письмо в лог вместо отправки.
type LogSender struct {
	log *slog.Logger
}

func (s *LogSender) Send(_ context.Context, msg Message) error {
	s.log.Info("outgoing email (SMTP disabled)",
		slog.String("to", msg.To),
		slog.String("subject", msg.Subject),
		slog.String("body", msg.Text),
	)
	return nil
}
