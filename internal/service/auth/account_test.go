package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

// Прежде адрес оставался занятым навсегда: глобальный UNIQUE держал строку
// удалённого аккаунта, и повторная регистрация упиралась в 409, хотя
// GetByEmail отвечал «нет такого пользователя».
func TestDeletedAccountFreesItsEmail(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "reuse@example.com")
	h.DeleteAccount(t, u.ID)

	fresh := h.RegisterVerified(t, "reuse@example.com")
	if fresh.ID == u.ID {
		t.Fatal("re-registration reused the deleted account instead of creating a new one")
	}

	if _, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "reuse@example.com", Password: servicetest.Password,
	}); err != nil {
		t.Fatalf("login into the new account: %v", err)
	}
}

func TestRestoreBringsBackTheSameAccount(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "restore-ok@example.com")
	h.EnableTwoFactor(t, u)
	h.DeleteAccount(t, u.ID)

	restored, err := h.Auth.RestoreAccount(t.Context(), "restore-ok@example.com", servicetest.Password)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.ID != u.ID {
		t.Fatalf("restored account id = %s, want the original %s", restored.ID, u.ID)
	}

	// Настройки аккаунта переживают удаление: второй фактор как был включён,
	// так и остался, и вход после восстановления требует его снова.
	res, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "restore-ok@example.com", Password: servicetest.Password,
	})
	if err != nil {
		t.Fatalf("login after restore: %v", err)
	}
	if !res.MFARequired() {
		t.Fatal("restore lost the second factor")
	}
}

func TestRestoreRequiresPassword(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "restore-pwd@example.com")
	h.DeleteAccount(t, u.ID)

	_, err := h.Auth.RestoreAccount(t.Context(), "restore-pwd@example.com", "wrong-password")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// Неизвестный адрес отвечает ровно тем же, что и неверный пароль.
func TestRestoreHidesUnknownAccounts(t *testing.T) {
	h := servicetest.New(t)

	_, err := h.Auth.RestoreAccount(t.Context(), "ghost@example.com", servicetest.Password)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestRestoreOnLiveAccountIsRejected(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "restore-live@example.com")

	_, err := h.Auth.RestoreAccount(t.Context(), "restore-live@example.com", servicetest.Password)
	if !errors.Is(err, user.ErrAccountNotDeleted) {
		t.Fatalf("got %v, want ErrAccountNotDeleted", err)
	}
}

func TestRestoreFailsAfterTheWindow(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "restore-late@example.com")
	h.DeleteAccount(t, u.ID)
	h.AgeDeletion(t, u.ID, h.Account.RestoreWindow+time.Hour)

	_, err := h.Auth.RestoreAccount(t.Context(), "restore-late@example.com", servicetest.Password)
	if !errors.Is(err, user.ErrRestoreExpired) {
		t.Fatalf("got %v, want ErrRestoreExpired", err)
	}
}

// Подтверждённый аккаунт, занявший освободившийся адрес, отменяет
// восстановление: двух живых с одним email быть не может.
func TestRestoreRejectedWhenEmailTakenByNewAccount(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "restore-taken@example.com")
	h.DeleteAccount(t, u.ID)
	h.RegisterVerified(t, "restore-taken@example.com")

	_, err := h.Auth.RestoreAccount(t.Context(), "restore-taken@example.com", servicetest.Password)
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("got %v, want ErrEmailTaken", err)
	}
}

// А вот незавершённая чужая регистрация восстановление не блокирует: она
// ничего не доказывает, тогда как восстанавливающий предъявил пароль.
// Иначе вернуть аккаунт мешал бы любой, кто начал регистрацию на этот адрес.
func TestRestoreBeatsUnverifiedRegistration(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "restore-squat@example.com")
	h.DeleteAccount(t, u.ID)

	squatter := register(t, h, "restore-squat@example.com")

	restored, err := h.Auth.RestoreAccount(t.Context(), "restore-squat@example.com", servicetest.Password)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.ID != u.ID {
		t.Fatalf("restored id = %s, want %s", restored.ID, u.ID)
	}

	// Заявка сквоттера снесена вместе с попыткой занять адрес.
	if _, err := h.Repo.GetByID(t.Context(), squatter.User.ID); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("squatter's registration survived: %v", err)
	}
}

// ---- вход по удалённому аккаунту ----

// Иначе про возможность восстановления владелец не узнает никогда: вход
// отвечал бы «неверный email или пароль».
func TestLoginOnDeletedAccountPointsToRestore(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "login-deleted@example.com")
	h.DeleteAccount(t, u.ID)

	_, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "login-deleted@example.com", Password: servicetest.Password,
	})
	if !errors.Is(err, user.ErrAccountDeleted) {
		t.Fatalf("got %v, want ErrAccountDeleted", err)
	}
}

// Но только предъявившему верный пароль: иначе вход сообщал бы кому угодно,
// что адрес когда-то был зарегистрирован.
func TestLoginOnDeletedAccountHidesItFromStrangers(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "login-deleted-wrong@example.com")
	h.DeleteAccount(t, u.ID)

	_, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "login-deleted-wrong@example.com", Password: "wrong-password",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// После окончания окна аккаунт неотличим от несуществующего, даже если
// уборщик ещё не дошёл до строки.
func TestLoginOnExpiredDeletionLooksLikeUnknownAccount(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "login-expired@example.com")
	h.DeleteAccount(t, u.ID)
	h.AgeDeletion(t, u.ID, h.Account.RestoreWindow+time.Hour)

	_, err := h.Auth.Login(t.Context(), &auth.Login{
		Email: "login-expired@example.com", Password: servicetest.Password,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// ---- удаление и уборка ----

func TestDeleteReturnsRestoreDeadlineAndRevokesSessions(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "delete-session@example.com")
	session := h.Login(t, "delete-session@example.com", servicetest.Password)

	until := h.DeleteAccount(t, u.ID)
	if want := time.Now().Add(h.Account.RestoreWindow); until.Sub(want).Abs() > time.Minute {
		t.Errorf("restore deadline = %s, want ~%s", until, want)
	}

	if _, err := h.Auth.Refresh(t.Context(), session.Tokens.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("refresh after deletion: got %v, want ErrInvalidToken", err)
	}
}

func TestPurgeRemovesAccountsPastTheWindow(t *testing.T) {
	h := servicetest.New(t)
	fresh := h.RegisterVerified(t, "purge-fresh@example.com")
	stale := h.RegisterVerified(t, "purge-stale@example.com")
	h.DeleteAccount(t, fresh.ID)
	h.DeleteAccount(t, stale.ID)
	h.AgeDeletion(t, stale.ID, h.Account.RestoreWindow+time.Hour)

	purged, err := h.Repo.PurgeDeletedUsers(t.Context(), time.Now().Add(-h.Account.RestoreWindow))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	// Свежеудалённый по-прежнему восстановим.
	if _, err := h.Auth.RestoreAccount(t.Context(), "purge-fresh@example.com", servicetest.Password); err != nil {
		t.Fatalf("restore a recently deleted account: %v", err)
	}
	// Просроченный исчез совсем — теперь это просто неизвестный адрес.
	if _, err := h.Auth.RestoreAccount(t.Context(), "purge-stale@example.com", servicetest.Password); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("restore a purged account: got %v, want ErrInvalidCredentials", err)
	}
}
