package config

import (
	"strings"
	"testing"
	"time"
)

func validConfig() *Config {
	return &Config{
		Service: ServiceConfig{Env: "local"},
		JWT: JWTConfig{
			Secret:      strings.Repeat("x", 32),
			MFATokenTTL: 10 * time.Minute,
		},
		Mail: MailConfig{Transport: MailTransportLog},
		Codes: CodesConfig{
			TTL:            10 * time.Minute,
			ResendCooldown: time.Minute,
			MaxAttempts:    5,
		},
		Account: AccountConfig{RestoreWindow: 365 * 24 * time.Hour},
		QRLogin: QRLoginConfig{TTL: 2 * time.Minute},
	}
}

func TestValidateAcceptsSaneConfig(t *testing.T) {
	if err := validConfig().validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateRejectsShortSecret(t *testing.T) {
	cfg := validConfig()
	cfg.JWT.Secret = "too-short"

	if err := cfg.validate(); err == nil {
		t.Fatal("short JWT_SECRET accepted")
	}
}

// Лог вместо почты означает нерабочую регистрацию и второй фактор — вне
// локального запуска это ошибка конфигурации, а не режим.
func TestValidateRejectsLogMailOutsideLocal(t *testing.T) {
	cfg := validConfig()
	cfg.Service.Env = "production"

	if err := cfg.validate(); err == nil {
		t.Fatal("MAIL_TRANSPORT=log accepted in production")
	}
}

func httpMail() MailConfig {
	return MailConfig{
		Transport:  MailTransportHTTP,
		ServiceURL: "https://mail.example.com",
		ClientID:   "auth",
		Secret:     strings.Repeat("s", 32),
		Timeout:    5 * time.Second,
	}
}

func TestValidateAcceptsHTTPMail(t *testing.T) {
	cfg := validConfig()
	cfg.Mail = httpMail()

	if err := cfg.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

// В запросе к почтовику одноразовый код: открытый http допустим только на
// локальном стенде, где почтовик в той же docker-сети.
func TestValidateRejectsPlainHTTPMailOutsideLocal(t *testing.T) {
	cfg := validConfig()
	cfg.Service.Env = "production"
	cfg.Mail = httpMail()
	cfg.Mail.ServiceURL = "http://mail-service:8080"

	if err := cfg.validate(); err == nil {
		t.Fatal("plain http MAIL_SERVICE_URL accepted in production")
	}

	cfg.Service.Env = "local"
	if err := cfg.validate(); err != nil {
		t.Fatalf("plain http rejected locally: %v", err)
	}
}

// Частная сеть между серверами: http вне local — только по явному согласию.
func TestValidateAllowsInsecureMailOnlyExplicitly(t *testing.T) {
	cfg := validConfig()
	cfg.Service.Env = "production"
	cfg.Mail = httpMail()
	cfg.Mail.ServiceURL = "http://10.0.0.5"

	if err := cfg.validate(); err == nil {
		t.Fatal("plain http accepted without MAIL_ALLOW_INSECURE")
	}
	cfg.Mail.AllowInsecure = true
	if err := cfg.validate(); err != nil {
		t.Fatalf("MAIL_ALLOW_INSECURE=true rejected: %v", err)
	}
}

func TestValidateRejectsCAFileWithoutHTTPS(t *testing.T) {
	cfg := validConfig()
	cfg.Mail = httpMail()
	cfg.Mail.ServiceURL = "http://mail-service:8080"
	cfg.Mail.CAFile = "/etc/mail-ca/root.crt"

	if err := cfg.validate(); err == nil {
		t.Fatal("MAIL_CA_FILE with http URL accepted")
	}
}

func TestValidateRejectsIncompleteHTTPMail(t *testing.T) {
	broken := map[string]func(*MailConfig){
		"no url":       func(m *MailConfig) { m.ServiceURL = "" },
		"bad scheme":   func(m *MailConfig) { m.ServiceURL = "ftp://mail.example.com" },
		"short secret": func(m *MailConfig) { m.Secret = "short" },
		"no client":    func(m *MailConfig) { m.ClientID = "" },
		"zero timeout": func(m *MailConfig) { m.Timeout = 0 },
	}
	for name, mutate := range broken {
		cfg := validConfig()
		cfg.Mail = httpMail()
		mutate(&cfg.Mail)

		if err := cfg.validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateRejectsUnknownMailTransport(t *testing.T) {
	cfg := validConfig()
	cfg.Mail.Transport = "pigeon"

	if err := cfg.validate(); err == nil {
		t.Fatal("unknown MAIL_TRANSPORT accepted")
	}
}

// Кулдаун длиннее TTL запирает пользователя: код уже протух, а новый
// запросить ещё нельзя.
func TestValidateRejectsCooldownLongerThanTTL(t *testing.T) {
	cfg := validConfig()
	cfg.Codes.ResendCooldown = 20 * time.Minute

	if err := cfg.validate(); err == nil {
		t.Fatal("cooldown longer than the code TTL accepted")
	}
}

// MFA-токен короче кода отнимает право предъявить ещё живой код.
func TestValidateRejectsMFATokenShorterThanCode(t *testing.T) {
	cfg := validConfig()
	cfg.JWT.MFATokenTTL = time.Minute

	if err := cfg.validate(); err == nil {
		t.Fatal("MFA token TTL shorter than the code TTL accepted")
	}
}

// Нулевое окно восстановления означало бы, что удалённый аккаунт
// невосстановим с первой же секунды, — так включать это можно только явно.
func TestValidateRejectsNonPositiveRestoreWindow(t *testing.T) {
	cfg := validConfig()
	cfg.Account.RestoreWindow = 0

	if err := cfg.validate(); err == nil {
		t.Fatal("zero ACCOUNT_RESTORE_WINDOW accepted")
	}
}

func TestValidateRejectsBadQRTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, time.Hour} {
		cfg := validConfig()
		cfg.QRLogin.TTL = ttl

		if err := cfg.validate(); err == nil {
			t.Fatalf("AUTH_QR_TTL=%s accepted", ttl)
		}
	}
}

func TestParseDurationAcceptsSecondsAndGoSyntax(t *testing.T) {
	t.Setenv("TEST_TTL", "90")
	if got := parseDuration("TEST_TTL", time.Hour); got != 90*time.Second {
		t.Errorf("plain seconds: got %s, want 1m30s", got)
	}

	t.Setenv("TEST_TTL", "15m")
	if got := parseDuration("TEST_TTL", time.Hour); got != 15*time.Minute {
		t.Errorf("go duration: got %s, want 15m", got)
	}

	t.Setenv("TEST_TTL", "nonsense")
	if got := parseDuration("TEST_TTL", time.Hour); got != time.Hour {
		t.Errorf("fallback: got %s, want 1h", got)
	}
}
