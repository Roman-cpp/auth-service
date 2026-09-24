package auth_test

import (
	"errors"
	"testing"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

func register(t *testing.T, h *servicetest.Harness, email string) *auth.RegisterResult {
	t.Helper()
	res, err := h.Auth.Register(t.Context(), &auth.Register{
		LastName: "Иванов", FirstName: "Иван", Email: email, Password: servicetest.Password,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	return res
}

func TestRegisterDoesNotOpenSession(t *testing.T) {
	h := servicetest.New(t)
	res := register(t, h, "fresh@example.com")

	if res.Challenge == nil {
		t.Fatal("expected a code challenge")
	}
	if h.Mails.Count() != 1 {
		t.Fatalf("emails sent = %d, want 1", h.Mails.Count())
	}

	// До подтверждения почты вход закрыт — иначе второй фактор регистрации
	// не значит ничего.
	_, err := h.Auth.Login(t.Context(), &auth.Login{Email: "fresh@example.com", Password: servicetest.Password})
	if !errors.Is(err, auth.ErrEmailNotVerified) {
		t.Fatalf("login before verification: got %v, want ErrEmailNotVerified", err)
	}
}

func TestVerifyEmailOpensSession(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "verify@example.com")
	code := h.Mails.Last(t).Code

	res, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "verify@example.com", Code: code})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if res.Tokens == nil || res.Tokens.AccessToken == "" || res.Tokens.RefreshToken == "" {
		t.Fatal("expected a token pair after verification")
	}

	if _, err := h.Auth.Login(t.Context(), &auth.Login{Email: "verify@example.com", Password: servicetest.Password}); err != nil {
		t.Fatalf("login after verification: %v", err)
	}
}

func TestVerifyEmailRejectsWrongCode(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "wrong@example.com")

	_, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "wrong@example.com", Code: "000000"})
	if !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

// Неизвестный адрес отвечает ровно тем же, что и неверный код: иначе
// эндпоинт превращается в средство проверки, зарегистрирован ли человек.
func TestVerifyEmailHidesUnknownAccounts(t *testing.T) {
	h := servicetest.New(t)

	_, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "nobody@example.com", Code: "123456"})
	if !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("got %v, want ErrCodeInvalid", err)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "once@example.com")
	code := h.Mails.Last(t).Code

	if _, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "once@example.com", Code: code}); err != nil {
		t.Fatalf("first verify: %v", err)
	}

	_, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "once@example.com", Code: code})
	if !errors.Is(err, auth.ErrEmailVerified) {
		t.Fatalf("second verify: got %v, want ErrEmailVerified", err)
	}
}

func TestCodeAttemptsAreLimited(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "bruteforce@example.com")
	code := h.Mails.Last(t).Code

	// MaxAttempts в харнессе = 3.
	for i := range 3 {
		_, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "bruteforce@example.com", Code: "000000"})
		if !errors.Is(err, auth.ErrCodeInvalid) {
			t.Fatalf("attempt %d: got %v, want ErrCodeInvalid", i+1, err)
		}
	}

	// Верный код после исчерпания попыток тоже не принимается — иначе
	// лимит обходится подбором до последнего шанса.
	_, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "bruteforce@example.com", Code: code})
	if !errors.Is(err, auth.ErrCodeAttempts) {
		t.Fatalf("after limit: got %v, want ErrCodeAttempts", err)
	}
}

func TestExpiredCodeIsRejected(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "stale@example.com")
	code := h.Mails.Last(t).Code

	u, err := h.Repo.GetByEmail(t.Context(), "stale@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	h.ExpireCode(t, u.ID, auth.CodePurposeEmailVerify)

	_, err = h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "stale@example.com", Code: code})
	if !errors.Is(err, auth.ErrCodeExpired) {
		t.Fatalf("got %v, want ErrCodeExpired", err)
	}
}

// Повторный запрос внутри кулдауна не ошибка, а отказ от второго письма:
// пользователю возвращаются сроки уже действующего кода.
func TestResendWithinCooldownDoesNotSendSecondEmail(t *testing.T) {
	h := servicetest.New(t)
	first := register(t, h, "resend@example.com")

	again, err := h.Auth.ResendEmailVerification(t.Context(), "resend@example.com")
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if h.Mails.Count() != 1 {
		t.Fatalf("emails sent = %d, want 1 (cooldown must suppress the second)", h.Mails.Count())
	}
	if !again.ExpiresAt.Equal(first.Challenge.ExpiresAt) {
		t.Errorf("expires_at = %s, want the active code's %s", again.ExpiresAt, first.Challenge.ExpiresAt)
	}

	// Код из первого письма обязан продолжать работать.
	if _, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{
		Email: "resend@example.com", Code: h.Mails.Last(t).Code,
	}); err != nil {
		t.Fatalf("verify with the original code: %v", err)
	}
}

// После успешного ввода кулдаун не должен ссылаться на использованный код.
func TestCodeIsReissuedAfterBeingConsumed(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "reissue@example.com")

	if _, err := h.Auth.StartEnableTwoFactor(t.Context(), u.ID, servicetest.Password); err != nil {
		t.Fatalf("start enable 2fa: %v", err)
	}
	if h.Mails.Count() != 2 {
		t.Fatalf("emails sent = %d, want 2 (verification + 2fa enable)", h.Mails.Count())
	}
}

func TestResendSupersedesPreviousCode(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "supersede@example.com")
	first := h.Mails.Last(t).Code

	u, err := h.Repo.GetByEmail(t.Context(), "supersede@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	h.PassCooldown(t, u.ID, auth.CodePurposeEmailVerify)

	if _, err := h.Auth.ResendEmailVerification(t.Context(), "supersede@example.com"); err != nil {
		t.Fatalf("resend: %v", err)
	}
	second := h.Mails.Last(t).Code
	if first == second {
		t.Skip("сгенерированы одинаковые коды — маловероятная случайность, проверка неинформативна")
	}

	if _, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "supersede@example.com", Code: first}); !errors.Is(err, auth.ErrCodeInvalid) {
		t.Fatalf("old code: got %v, want ErrCodeInvalid", err)
	}
	if _, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "supersede@example.com", Code: second}); err != nil {
		t.Fatalf("new code: %v", err)
	}
}

// Повторная отправка на неизвестный адрес обязана выглядеть успешной
// и при этом ничего не отправлять.
func TestResendHidesUnknownAccounts(t *testing.T) {
	h := servicetest.New(t)

	challenge, err := h.Auth.ResendEmailVerification(t.Context(), "ghost@example.com")
	if err != nil {
		t.Fatalf("resend: %v", err)
	}
	if challenge == nil {
		t.Fatal("expected a challenge for an unknown address")
	}
	if h.Mails.Count() != 0 {
		t.Fatalf("emails sent = %d, want 0", h.Mails.Count())
	}
}

// Незавершённая регистрация не должна занимать адрес навсегда.
func TestUnverifiedRegistrationCanBeReplaced(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "squat@example.com")

	u, err := h.Repo.GetByEmail(t.Context(), "squat@example.com")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	h.PassCooldown(t, u.ID, auth.CodePurposeEmailVerify)

	if _, err := h.Auth.Register(t.Context(), &auth.Register{
		LastName: "Петров", FirstName: "Пётр", Email: "squat@example.com", Password: "another-password",
	}); err != nil {
		t.Fatalf("re-register unverified: %v", err)
	}

	code := h.Mails.Last(t).Code
	if _, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "squat@example.com", Code: code}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := h.Auth.Login(t.Context(), &auth.Login{Email: "squat@example.com", Password: "another-password"}); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
}

func TestVerifiedAccountCannotBeOverwritten(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "taken@example.com")

	_, err := h.Auth.Register(t.Context(), &auth.Register{
		LastName: "Петров", FirstName: "Пётр", Email: "taken@example.com", Password: "hijack-attempt",
	})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("got %v, want ErrEmailTaken", err)
	}
}

func TestEmailIsCaseInsensitive(t *testing.T) {
	h := servicetest.New(t)
	register(t, h, "  MiXeD@Example.COM ")
	code := h.Mails.Last(t).Code

	if _, err := h.Auth.VerifyEmail(t.Context(), &auth.VerifyCode{Email: "mixed@example.com", Code: code}); err != nil {
		t.Fatalf("verify with lowercase: %v", err)
	}
	if _, err := h.Auth.Login(t.Context(), &auth.Login{Email: "MIXED@EXAMPLE.COM", Password: servicetest.Password}); err != nil {
		t.Fatalf("login with uppercase: %v", err)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "pwd@example.com")

	_, err := h.Auth.Login(t.Context(), &auth.Login{Email: "pwd@example.com", Password: "nope"})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginOnUnknownEmailLooksTheSame(t *testing.T) {
	h := servicetest.New(t)

	_, err := h.Auth.Login(t.Context(), &auth.Login{Email: "nobody@example.com", Password: servicetest.Password})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}
