package auth_test

import (
	"errors"
	"testing"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

const newPassword = "another-correct-horse"

// requestReset проводит заявку на сброс и достаёт код из письма.
func requestReset(t *testing.T, h *servicetest.Harness, email string) string {
	t.Helper()

	if _, err := h.Auth.StartPasswordReset(t.Context(), email); err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	return h.Mails.Last(t).Code
}

// ---- сброс пароля ----

func TestResetPasswordReplacesPassword(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "reset-ok@example.com")
	code := requestReset(t, h, "reset-ok@example.com")

	if err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-ok@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	if _, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "reset-ok@example.com", Password: newPassword,
	}); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}

	_, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "reset-ok@example.com", Password: servicetest.Password,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("login with the old password: got %v, want ErrInvalidCredentials", err)
	}
}

// Сброс — путь восстановления после компрометации: тот, кто успел войти по
// старому паролю, обязан потерять доступ.
func TestResetPasswordRevokesExistingSessions(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "reset-sessions@example.com")
	session := h.Login(t, "reset-sessions@example.com", servicetest.Password)

	code := requestReset(t, h, "reset-sessions@example.com")
	if err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-sessions@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	_, err := h.Auth.Refresh(t.Context(), session.Tokens.RefreshToken)
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("refresh with the pre-reset token: got %v, want ErrInvalidToken", err)
	}
}

// Код сброса приходит на ту же почту, что и код второго фактора. Открывай
// сброс сессию — доступ к ящику отменял бы 2FA целиком.
func TestResetPasswordDoesNotBypassTwoFactor(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "reset-2fa@example.com")
	h.EnableTwoFactor(t, u)

	code := requestReset(t, h, "reset-2fa@example.com")
	if err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-2fa@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	res := h.Login(t, "reset-2fa@example.com", newPassword)
	if !res.MFARequired() {
		t.Fatal("password reset opened a session without the second factor")
	}
}

func TestResetPasswordRejectsWrongCode(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "reset-wrong@example.com")
	requestReset(t, h, "reset-wrong@example.com")

	err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-wrong@example.com", Code: "000000", Password: newPassword,
	})
	if !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}

	// Пароль обязан остаться прежним.
	if _, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "reset-wrong@example.com", Password: servicetest.Password,
	}); err != nil {
		t.Fatalf("login with the old password: %v", err)
	}
}

func TestResetCodeIsSingleUse(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "reset-once@example.com")
	code := requestReset(t, h, "reset-once@example.com")

	if err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-once@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("first reset: %v", err)
	}

	err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-once@example.com", Code: code, Password: "third-password-here",
	})
	if !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("second reset: got %v, want ErrCodeInvalid", err)
	}
}

// Код одного назначения не должен работать в сценарии другого — иначе
// разделение по purpose не значит ничего.
func TestResetPasswordRejectsCodeIssuedForAnotherPurpose(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "reset-purpose@example.com")

	if _, err := h.Auth.StartEnableTwoFactor(t.Context(), u.ID, servicetest.Password); err != nil {
		t.Fatalf("start enable 2fa: %v", err)
	}
	foreign := h.Mails.Last(t).Code

	err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-purpose@example.com", Code: foreign, Password: newPassword,
	})
	if !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

// Неизвестный адрес отвечает ровно так же, как известный, и не шлёт письма.
func TestForgotPasswordHidesUnknownAccounts(t *testing.T) {
	h := servicetest.New(t)

	challenge, err := h.Auth.StartPasswordReset(t.Context(), "ghost@example.com")
	if err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected a challenge for an unknown address")
	}
	if h.Mails.Count() != 0 {
		t.Fatalf("emails sent = %d, want 0", h.Mails.Count())
	}
}

// Неподтверждённому адресу письмо о сбросе не уходит: иначе на чужой ящик,
// который ещё никто не подтвердил, письма заказывает кто угодно.
func TestForgotPasswordIgnoresUnverifiedAccounts(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "reset-unverified@example.com")

	if _, err := h.Auth.StartPasswordReset(t.Context(), "reset-unverified@example.com"); err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	if h.Mails.Count() != 1 {
		t.Fatalf("emails sent = %d, want 1 (registration only)", h.Mails.Count())
	}

	// И код, разумеется, не принимается.
	err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-unverified@example.com", Code: h.Mails.Last(t).Code, Password: newPassword,
	})
	if !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

func TestResetPasswordRejectsCurrentPassword(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "reset-same@example.com")
	code := requestReset(t, h, "reset-same@example.com")

	err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-same@example.com", Code: code, Password: servicetest.Password,
	})
	if !errors.Is(err, auth.ErrPasswordUnchanged) {
		t.Fatalf("got %v, want ErrPasswordUnchanged", err)
	}
}

// Совпавший пароль — ошибка ввода, а не попытка подбора: код после неё
// остаётся живым, и повторить сброс можно им же, без нового письма.
func TestResetPasswordKeepsCodeAfterUnchangedPassword(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "reset-retry@example.com")
	code := requestReset(t, h, "reset-retry@example.com")

	err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-retry@example.com", Code: code, Password: servicetest.Password,
	})
	if !errors.Is(err, auth.ErrPasswordUnchanged) {
		t.Fatalf("same password: got %v, want ErrPasswordUnchanged", err)
	}

	if err := h.Auth.ResetPassword(t.Context(), &auth.ResetPassword{
		Email: "reset-retry@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("retry with the same code: %v", err)
	}
	h.Login(t, "reset-retry@example.com", newPassword)
}

// ---- смена пароля ----

func TestChangePasswordReplacesPassword(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "change-ok@example.com")

	res, err := h.Auth.ChangePassword(t.Context(), u.ID, &auth.ChangePassword{
		CurrentPassword: servicetest.Password, NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	if res.Tokens == nil || res.Tokens.RefreshToken == "" {
		t.Fatal("expected a fresh token pair for the caller")
	}

	if _, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "change-ok@example.com", Password: newPassword,
	}); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
	if _, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "change-ok@example.com", Password: servicetest.Password,
	}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("login with the old password: got %v, want ErrInvalidCredentials", err)
	}
}

// Перехваченная сессия не должна давать права сменить пароль.
func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "change-pwd@example.com")

	_, err := h.Auth.ChangePassword(t.Context(), u.ID, &auth.ChangePassword{
		CurrentPassword: "wrong-password", NewPassword: newPassword,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// Остальные устройства разлогиниваются, вызывающий клиент — нет: он получает
// новую пару взамен отозванной.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "change-sessions@example.com")
	other := h.Login(t, "change-sessions@example.com", servicetest.Password)

	res, err := h.Auth.ChangePassword(t.Context(), u.ID, &auth.ChangePassword{
		CurrentPassword: servicetest.Password, NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}

	if _, err := h.Auth.Refresh(t.Context(), other.Tokens.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("other device: got %v, want ErrInvalidToken", err)
	}
	if _, err := h.Auth.Refresh(t.Context(), res.Tokens.RefreshToken); err != nil {
		t.Fatalf("caller's fresh token: %v", err)
	}
}

func TestChangePasswordRejectsSamePassword(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "change-same@example.com")

	_, err := h.Auth.ChangePassword(t.Context(), u.ID, &auth.ChangePassword{
		CurrentPassword: servicetest.Password, NewPassword: servicetest.Password,
	})
	if !errors.Is(err, auth.ErrPasswordUnchanged) {
		t.Fatalf("got %v, want ErrPasswordUnchanged", err)
	}

	// Сессии при отказе трогать нельзя.
	if _, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "change-same@example.com", Password: servicetest.Password,
	}); err != nil {
		t.Fatalf("login after a rejected change: %v", err)
	}
}
