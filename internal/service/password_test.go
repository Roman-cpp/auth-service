package service

import (
	"errors"
	"testing"

	"github.com/krypton/auth-service/internal/domain/user"
)

const newPassword = "another-correct-horse"

// requestReset проводит заявку на сброс и достаёт код из письма.
func requestReset(t *testing.T, h *harness, email string) string {
	t.Helper()

	if _, err := h.auth.StartPasswordReset(t.Context(), email); err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	return h.mails.last(t).code
}

func login(t *testing.T, h *harness, email, password string) *user.LoginResult {
	t.Helper()

	res, err := h.auth.Login(t.Context(), &user.Login{Email: email, Password: password})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return res
}

// ---- сброс пароля ----

func TestResetPasswordReplacesPassword(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "reset-ok@example.com")
	code := requestReset(t, h, "reset-ok@example.com")

	if err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-ok@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	if _, err := h.auth.Login(t.Context(), &user.Login{
		Email: "reset-ok@example.com", Password: newPassword,
	}); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}

	_, err := h.auth.Login(t.Context(), &user.Login{
		Email: "reset-ok@example.com", Password: testPassword,
	})
	if !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("login with the old password: got %v, want ErrInvalidCredentials", err)
	}
}

// Сброс — путь восстановления после компрометации: тот, кто успел войти по
// старому паролю, обязан потерять доступ.
func TestResetPasswordRevokesExistingSessions(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "reset-sessions@example.com")
	session := login(t, h, "reset-sessions@example.com", testPassword)

	code := requestReset(t, h, "reset-sessions@example.com")
	if err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-sessions@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	_, err := h.auth.Refresh(t.Context(), session.Tokens.RefreshToken)
	if !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("refresh with the pre-reset token: got %v, want ErrInvalidToken", err)
	}
}

// Код сброса приходит на ту же почту, что и код второго фактора. Открывай
// сброс сессию — доступ к ящику отменял бы 2FA целиком.
func TestResetPasswordDoesNotBypassTwoFactor(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "reset-2fa@example.com")
	enableTwoFactor(t, h, u)

	code := requestReset(t, h, "reset-2fa@example.com")
	if err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-2fa@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}

	res := login(t, h, "reset-2fa@example.com", newPassword)
	if !res.MFARequired() {
		t.Fatal("password reset opened a session without the second factor")
	}
}

func TestResetPasswordRejectsWrongCode(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "reset-wrong@example.com")
	requestReset(t, h, "reset-wrong@example.com")

	err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-wrong@example.com", Code: "000000", Password: newPassword,
	})
	if !errors.Is(err, user.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}

	// Пароль обязан остаться прежним.
	if _, err := h.auth.Login(t.Context(), &user.Login{
		Email: "reset-wrong@example.com", Password: testPassword,
	}); err != nil {
		t.Fatalf("login with the old password: %v", err)
	}
}

func TestResetCodeIsSingleUse(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "reset-once@example.com")
	code := requestReset(t, h, "reset-once@example.com")

	if err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-once@example.com", Code: code, Password: newPassword,
	}); err != nil {
		t.Fatalf("first reset: %v", err)
	}

	err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-once@example.com", Code: code, Password: "third-password-here",
	})
	if !errors.Is(err, user.ErrCodeInvalid) {
		t.Fatalf("second reset: got %v, want ErrCodeInvalid", err)
	}
}

// Код одного назначения не должен работать в сценарии другого — иначе
// разделение по purpose не значит ничего.
func TestResetPasswordRejectsCodeIssuedForAnotherPurpose(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "reset-purpose@example.com")

	if _, err := h.auth.StartEnableTwoFactor(t.Context(), u.ID, testPassword); err != nil {
		t.Fatalf("start enable 2fa: %v", err)
	}
	foreign := h.mails.last(t).code

	err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-purpose@example.com", Code: foreign, Password: newPassword,
	})
	if !errors.Is(err, user.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

// Неизвестный адрес отвечает ровно так же, как известный, и не шлёт письма.
func TestForgotPasswordHidesUnknownAccounts(t *testing.T) {
	h := newHarness(t)

	challenge, err := h.auth.StartPasswordReset(t.Context(), "ghost@example.com")
	if err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected a challenge for an unknown address")
	}
	if h.mails.count() != 0 {
		t.Fatalf("emails sent = %d, want 0", h.mails.count())
	}
}

// Неподтверждённому адресу письмо о сбросе не уходит: иначе на чужой ящик,
// который ещё никто не подтвердил, письма заказывает кто угодно.
func TestForgotPasswordIgnoresUnverifiedAccounts(t *testing.T) {
	h := newHarness(t)
	register(t, h, "reset-unverified@example.com")

	if _, err := h.auth.StartPasswordReset(t.Context(), "reset-unverified@example.com"); err != nil {
		t.Fatalf("start password reset: %v", err)
	}
	if h.mails.count() != 1 {
		t.Fatalf("emails sent = %d, want 1 (registration only)", h.mails.count())
	}

	// И код, разумеется, не принимается.
	err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-unverified@example.com", Code: h.mails.last(t).code, Password: newPassword,
	})
	if !errors.Is(err, user.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

func TestResetPasswordRejectsCurrentPassword(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "reset-same@example.com")
	code := requestReset(t, h, "reset-same@example.com")

	err := h.auth.ResetPassword(t.Context(), &user.ResetPassword{
		Email: "reset-same@example.com", Code: code, Password: testPassword,
	})
	if !errors.Is(err, user.ErrPasswordUnchanged) {
		t.Fatalf("got %v, want ErrPasswordUnchanged", err)
	}
}

// ---- смена пароля ----

func TestChangePasswordReplacesPassword(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "change-ok@example.com")

	res, err := h.auth.ChangePassword(t.Context(), u.ID, &user.ChangePassword{
		CurrentPassword: testPassword, NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}
	if res.Tokens == nil || res.Tokens.RefreshToken == "" {
		t.Fatal("expected a fresh token pair for the caller")
	}

	if _, err := h.auth.Login(t.Context(), &user.Login{
		Email: "change-ok@example.com", Password: newPassword,
	}); err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
	if _, err := h.auth.Login(t.Context(), &user.Login{
		Email: "change-ok@example.com", Password: testPassword,
	}); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("login with the old password: got %v, want ErrInvalidCredentials", err)
	}
}

// Перехваченная сессия не должна давать права сменить пароль.
func TestChangePasswordRequiresCurrentPassword(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "change-pwd@example.com")

	_, err := h.auth.ChangePassword(t.Context(), u.ID, &user.ChangePassword{
		CurrentPassword: "wrong-password", NewPassword: newPassword,
	})
	if !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// Остальные устройства разлогиниваются, вызывающий клиент — нет: он получает
// новую пару взамен отозванной.
func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "change-sessions@example.com")
	other := login(t, h, "change-sessions@example.com", testPassword)

	res, err := h.auth.ChangePassword(t.Context(), u.ID, &user.ChangePassword{
		CurrentPassword: testPassword, NewPassword: newPassword,
	})
	if err != nil {
		t.Fatalf("change password: %v", err)
	}

	if _, err := h.auth.Refresh(t.Context(), other.Tokens.RefreshToken); !errors.Is(err, user.ErrInvalidToken) {
		t.Fatalf("other device: got %v, want ErrInvalidToken", err)
	}
	if _, err := h.auth.Refresh(t.Context(), res.Tokens.RefreshToken); err != nil {
		t.Fatalf("caller's fresh token: %v", err)
	}
}

func TestChangePasswordRejectsSamePassword(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "change-same@example.com")

	_, err := h.auth.ChangePassword(t.Context(), u.ID, &user.ChangePassword{
		CurrentPassword: testPassword, NewPassword: testPassword,
	})
	if !errors.Is(err, user.ErrPasswordUnchanged) {
		t.Fatalf("got %v, want ErrPasswordUnchanged", err)
	}

	// Сессии при отказе трогать нельзя.
	if _, err := h.auth.Login(t.Context(), &user.Login{
		Email: "change-same@example.com", Password: testPassword,
	}); err != nil {
		t.Fatalf("login after a rejected change: %v", err)
	}
}
