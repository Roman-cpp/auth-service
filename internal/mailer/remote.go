package mailer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
)

// RemoteMailer отправляет письма через mail-service подписанным HTTP-запросом
// с именем шаблона и данными. Почтовик ставит письмо в очередь и отвечает 202
// сразу; доставка и повторы — на его стороне.
type RemoteMailer struct {
	endpoint *url.URL
	clientID string
	secret   []byte
	http     *http.Client
	now      func() time.Time
}

func NewRemote(cfg config.MailConfig) (*RemoteMailer, error) {
	endpoint, err := url.Parse(cfg.ServiceURL)
	if err != nil {
		return nil, fmt.Errorf("MAIL_SERVICE_URL: %w", err)
	}
	// Путь входит в подпись, поэтому собирается здесь один раз и в таком
	// же виде уходит в запрос.
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/api/v1/messages"
	endpoint.RawQuery, endpoint.Fragment = "", ""

	client := &http.Client{Timeout: cfg.Timeout}
	if cfg.CAFile != "" {
		transport, err := pinnedTransport(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		client.Transport = transport
	}

	return &RemoteMailer{
		endpoint: endpoint,
		clientID: cfg.ClientID,
		secret:   []byte(cfg.Secret),
		http:     client,
		now:      time.Now,
	}, nil
}

// pinnedTransport доверяет только CA из файла: почтовик без публичного
// сертификата выпускает его своим CA, и принимать от него любой сертификат,
// подписанный кем угодно из системного списка, незачем. Файл читается на
// старте — ошибка в пути роняет сервис сразу, а не на первом письме.
func pinnedTransport(caFile string) (*http.Transport, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("MAIL_CA_FILE: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("MAIL_CA_FILE: no PEM certificates in %s", caFile)
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return transport, nil
}

// sendRequest — тело POST /api/v1/messages (см. README mail-service).
type sendRequest struct {
	Template string      `json:"template"`
	To       string      `json:"to"`
	Locale   string      `json:"locale"`
	Data     codePayload `json:"data"`
}

type codePayload struct {
	Purpose    string `json:"purpose"`
	Code       string `json:"code"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// SendCode ставит письмо в очередь почтовика. ref — ключ идемпотентности
// (id выпущенного кода): повтор после сетевой ошибки не создаст второго
// письма, почтовик вернёт уже принятое.
func (m *RemoteMailer) SendCode(ctx context.Context, to string, purpose auth.CodePurpose, code string, ttl time.Duration, ref string) error {
	body, err := json.Marshal(sendRequest{
		Template: "auth.code",
		To:       to,
		Locale:   "ru",
		Data: codePayload{
			Purpose:    string(purpose),
			Code:       code,
			TTLMinutes: max(1, int(math.Round(ttl.Minutes()))),
		},
	})
	if err != nil {
		return fmt.Errorf("encode request: %w", err)
	}

	// Одна повторная попытка — только на сетевую ошибку или 5xx: с тем же
	// Idempotency-Key это безопасно. Ошибки 4xx повтором не лечатся.
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
		}
		err := m.post(ctx, body, ref)
		if err == nil {
			return nil
		}
		lastErr = err
		var transient *transientError
		if !errors.As(err, &transient) {
			return err
		}
	}
	return lastErr
}

func (m *RemoteMailer) post(ctx context.Context, body []byte, ref string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	timestamp := strconv.FormatInt(m.now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", m.clientID)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", hex.EncodeToString(Sign(m.secret, timestamp, http.MethodPost, m.endpoint.Path, body)))
	if ref != "" {
		req.Header.Set("Idempotency-Key", ref)
	}

	resp, err := m.http.Do(req)
	if err != nil {
		return &transientError{fmt.Errorf("mail-service request: %w", err)}
	}
	defer resp.Body.Close()

	// 202 — принято, 200 — уже было принято раньше (повтор по ключу).
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil
	}

	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&envelope)
	err = fmt.Errorf("mail-service responded %d %s: %s", resp.StatusCode, envelope.Error.Code, envelope.Error.Message)
	if resp.StatusCode >= http.StatusInternalServerError {
		return &transientError{err}
	}
	return err
}

// transientError помечает ошибки, после которых запрос имеет смысл повторить.
type transientError struct {
	err error
}

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }
