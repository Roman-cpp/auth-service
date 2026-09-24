package auth_test

import (
	"errors"
	"testing"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

func TestEnableTwoFactorRequiresPassword(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "enable-pwd@example.com")

	_, err := h.Auth.StartEnableTwoFactor(t.Context(), u.ID, "wrong-password")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// Включение второго фактора без подтверждения кодом означало бы, что
// пользователь может запереть себя на недоступном ящике.
func TestEnableTwoFactorRequiresEmailedCode(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "enable-code@example.com")

	if _, err := h.Auth.StartEnableTwoFactor(t.Context(), u.ID, servicetest.Password); err != nil {
		t.Fatalf("start: %v", err)
	}

	if _, err := h.Auth.ConfirmEnableTwoFactor(t.Context(), u.ID, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("confirm with wrong code: got %v, want ErrCodeInvalid", err)
	}

	stored, err := h.Repo.GetByID(t.Context(), u.ID)
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if stored.TwoFactorEnabled {
		t.Fatal("two-factor got enabled without a valid code")
	}
}

func TestLoginWithTwoFactorRequiresSecondStep(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-login@example.com")
	h.EnableTwoFactor(t, u)

	res, err := h.Auth.Login(t.Context(), &auth.Login{Email: "2fa-login@example.com", Password: servicetest.Password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !res.MFARequired() {
		t.Fatal("expected the second factor to be required")
	}
	if res.Tokens != nil {
		t.Fatal("session opened before the second factor")
	}
	if res.MFAToken == "" {
		t.Fatal("expected an MFA token")
	}

	code := h.Mails.Last(t).Code
	session, err := h.Auth.VerifyMFA(t.Context(), res.MFAToken, code)
	if err != nil {
		t.Fatalf("verify mfa: %v", err)
	}
	if session.Tokens == nil || session.Tokens.AccessToken == "" {
		t.Fatal("expected a token pair after the second factor")
	}
}

func TestVerifyMFARejectsWrongCode(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-wrong@example.com")
	h.EnableTwoFactor(t, u)

	res, err := h.Auth.Login(t.Context(), &auth.Login{Email: "2fa-wrong@example.com", Password: servicetest.Password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if _, err := h.Auth.VerifyMFA(t.Context(), res.MFAToken, "000000"); !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

func TestVerifyMFARejectsGarbageToken(t *testing.T) {
	h := servicetest.New(t)

	if _, err := h.Auth.VerifyMFA(t.Context(), "not-a-token", "123456"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("got %v, want ErrInvalidToken", err)
	}
}

// MFA-токен нельзя отозвать (он stateless), поэтому от повторного
// использования защищает погашенный код.
func TestMFATokenCannotBeReplayed(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-replay@example.com")
	h.EnableTwoFactor(t, u)

	res, err := h.Auth.Login(t.Context(), &auth.Login{Email: "2fa-replay@example.com", Password: servicetest.Password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	code := h.Mails.Last(t).Code

	if _, err := h.Auth.VerifyMFA(t.Context(), res.MFAToken, code); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := h.Auth.VerifyMFA(t.Context(), res.MFAToken, code); !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("replay: got %v, want ErrCodeInvalid", err)
	}
}

func TestResendMFAIssuesUsableCode(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-resend@example.com")
	h.EnableTwoFactor(t, u)

	res, err := h.Auth.Login(t.Context(), &auth.Login{Email: "2fa-resend@example.com", Password: servicetest.Password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	h.PassCooldown(t, u.ID, auth.CodePurposeMFALogin)

	refreshed, challenge, err := h.Auth.ResendMFACode(t.Context(), res.MFAToken)
	if err != nil {
		t.Fatalf("resend mfa: %v", err)
	}
	if refreshed == "" || challenge == nil {
		t.Fatal("expected a refreshed MFA token and challenge")
	}

	if _, err := h.Auth.VerifyMFA(t.Context(), refreshed, h.Mails.Last(t).Code); err != nil {
		t.Fatalf("verify with resent code: %v", err)
	}
}

func TestDisableTwoFactorRequiresPassword(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-disable-pwd@example.com")
	h.EnableTwoFactor(t, u)

	if _, err := h.Auth.DisableTwoFactor(t.Context(), u.ID, "wrong-password"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestDisableTwoFactorRestoresSingleStepLogin(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-disable@example.com")
	h.EnableTwoFactor(t, u)

	preview, err := h.Auth.DisableTwoFactor(t.Context(), u.ID, servicetest.Password)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if preview.TwoFactorEnabled {
		t.Fatal("preview still reports two-factor as enabled")
	}

	res, err := h.Auth.Login(t.Context(), &auth.Login{Email: "2fa-disable@example.com", Password: servicetest.Password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.MFARequired() {
		t.Fatal("second factor still required after disabling")
	}
}

func TestEnableTwoFactorTwiceConflicts(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "2fa-twice@example.com")
	h.EnableTwoFactor(t, u)

	if _, err := h.Auth.StartEnableTwoFactor(t.Context(), u.ID, servicetest.Password); !errors.Is(err, user.ErrTwoFactorState) {
		t.Fatalf("got %v, want ErrTwoFactorState", err)
	}
}
