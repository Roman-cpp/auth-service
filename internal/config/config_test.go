package config

import (
	"strings"
	"testing"
	"time"
)

func validConfig() *Config {
	return &Config{
		JWT: JWTConfig{
			Secret:      strings.Repeat("x", 32),
			MFATokenTTL: 10 * time.Minute,
		},
		SMTP: SMTPConfig{Transport: SMTPTransportSTARTTLS},
		Codes: CodesConfig{
			TTL:            10 * time.Minute,
			ResendCooldown: time.Minute,
			MaxAttempts:    5,
		},
		Account: AccountConfig{RestoreWindow: 365 * 24 * time.Hour},
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

func TestValidateRejectsUnknownTransport(t *testing.T) {
	cfg := validConfig()
	cfg.SMTP.Transport = "carrier-pigeon"

	if err := cfg.validate(); err == nil {
		t.Fatal("unknown SMTP transport accepted")
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
