package service

import (
	"errors"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
)

// Прежде адрес оставался занятым навсегда: глобальный UNIQUE держал строку
// удалённого аккаунта, и повторная регистрация упиралась в 409, хотя
// GetByEmail отвечал «нет такого пользователя».
func TestDeletedAccountFreesItsEmail(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "reuse@example.com")
	h.deleteAccount(t, u.ID)

	fresh := h.registerVerified(t, "reuse@example.com")
	if fresh.ID == u.ID {
		t.Fatal("re-registration reused the deleted account instead of creating a new one")
	}

	if _, err := h.auth.Login(t.Context(), &auth.Login{
		Email: "reuse@example.com", Password: testPassword,
	}); err != nil {
		t.Fatalf("login into the new account: %v", err)
	}
}

func TestRestoreBringsBackTheSameAccount(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "restore-ok@example.com")
	enableTwoFactor(t, h, u)
	h.deleteAccount(t, u.ID)

	restored, err := h.auth.RestoreAccount(t.Context(), "restore-ok@example.com", testPassword)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.ID != u.ID {
		t.Fatalf("restored account id = %s, want the original %s", restored.ID, u.ID)
	}

	// Настройки аккаунта переживают удаление: второй фактор как был включён,
	// так и остался, и вход после восстановления требует его снова.
	res, err := h.auth.Login(t.Context(), &auth.Login{
		Email: "restore-ok@example.com", Password: testPassword,
	})
	if err != nil {
		t.Fatalf("login after restore: %v", err)
	}
	if !res.MFARequired() {
		t.Fatal("restore lost the second factor")
	}
}

func TestRestoreRequiresPassword(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "restore-pwd@example.com")
	h.deleteAccount(t, u.ID)

	_, err := h.auth.RestoreAccount(t.Context(), "restore-pwd@example.com", "wrong-password")
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// Неизвестный адрес отвечает ровно тем же, что и неверный пароль.
func TestRestoreHidesUnknownAccounts(t *testing.T) {
	h := newHarness(t)

	_, err := h.auth.RestoreAccount(t.Context(), "ghost@example.com", testPassword)
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

func TestRestoreOnLiveAccountIsRejected(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "restore-live@example.com")

	_, err := h.auth.RestoreAccount(t.Context(), "restore-live@example.com", testPassword)
	if !errors.Is(err, user.ErrAccountNotDeleted) {
		t.Fatalf("got %v, want ErrAccountNotDeleted", err)
	}
}

func TestRestoreFailsAfterTheWindow(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "restore-late@example.com")
	h.deleteAccount(t, u.ID)
	h.ageDeletion(t, u.ID, h.account.RestoreWindow+time.Hour)

	_, err := h.auth.RestoreAccount(t.Context(), "restore-late@example.com", testPassword)
	if !errors.Is(err, user.ErrRestoreExpired) {
		t.Fatalf("got %v, want ErrRestoreExpired", err)
	}
}

// Подтверждённый аккаунт, занявший освободившийся адрес, отменяет
// восстановление: двух живых с одним email быть не может.
func TestRestoreRejectedWhenEmailTakenByNewAccount(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "restore-taken@example.com")
	h.deleteAccount(t, u.ID)
	h.registerVerified(t, "restore-taken@example.com")

	_, err := h.auth.RestoreAccount(t.Context(), "restore-taken@example.com", testPassword)
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("got %v, want ErrEmailTaken", err)
	}
}

// А вот незавершённая чужая регистрация восстановление не блокирует: она
// ничего не доказывает, тогда как восстанавливающий предъявил пароль.
// Иначе вернуть аккаунт мешал бы любой, кто начал регистрацию на этот адрес.
func TestRestoreBeatsUnverifiedRegistration(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "restore-squat@example.com")
	h.deleteAccount(t, u.ID)

	squatter := register(t, h, "restore-squat@example.com")

	restored, err := h.auth.RestoreAccount(t.Context(), "restore-squat@example.com", testPassword)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.ID != u.ID {
		t.Fatalf("restored id = %s, want %s", restored.ID, u.ID)
	}

	// Заявка сквоттера снесена вместе с попыткой занять адрес.
	if _, err := h.repo.GetByID(t.Context(), squatter.User.ID); !errors.Is(err, user.ErrNotFound) {
		t.Fatalf("squatter's registration survived: %v", err)
	}
}

// ---- вход по удалённому аккаунту ----

// Иначе про возможность восстановления владелец не узнает никогда: вход
// отвечал бы «неверный email или пароль».
func TestLoginOnDeletedAccountPointsToRestore(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "login-deleted@example.com")
	h.deleteAccount(t, u.ID)

	_, err := h.auth.Login(t.Context(), &auth.Login{
		Email: "login-deleted@example.com", Password: testPassword,
	})
	if !errors.Is(err, user.ErrAccountDeleted) {
		t.Fatalf("got %v, want ErrAccountDeleted", err)
	}
}

// Но только предъявившему верный пароль: иначе вход сообщал бы кому угодно,
// что адрес когда-то был зарегистрирован.
func TestLoginOnDeletedAccountHidesItFromStrangers(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "login-deleted-wrong@example.com")
	h.deleteAccount(t, u.ID)

	_, err := h.auth.Login(t.Context(), &auth.Login{
		Email: "login-deleted-wrong@example.com", Password: "wrong-password",
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// После окончания окна аккаунт неотличим от несуществующего, даже если
// уборщик ещё не дошёл до строки.
func TestLoginOnExpiredDeletionLooksLikeUnknownAccount(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "login-expired@example.com")
	h.deleteAccount(t, u.ID)
	h.ageDeletion(t, u.ID, h.account.RestoreWindow+time.Hour)

	_, err := h.auth.Login(t.Context(), &auth.Login{
		Email: "login-expired@example.com", Password: testPassword,
	})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("got %v, want ErrInvalidCredentials", err)
	}
}

// ---- удаление и уборка ----

func TestDeleteReturnsRestoreDeadlineAndRevokesSessions(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "delete-session@example.com")
	session := login(t, h, "delete-session@example.com", testPassword)

	until := h.deleteAccount(t, u.ID)
	if want := time.Now().Add(h.account.RestoreWindow); until.Sub(want).Abs() > time.Minute {
		t.Errorf("restore deadline = %s, want ~%s", until, want)
	}

	if _, err := h.auth.Refresh(t.Context(), session.Tokens.RefreshToken); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("refresh after deletion: got %v, want ErrInvalidToken", err)
	}
}

func TestPurgeRemovesAccountsPastTheWindow(t *testing.T) {
	h := newHarness(t)
	fresh := h.registerVerified(t, "purge-fresh@example.com")
	stale := h.registerVerified(t, "purge-stale@example.com")
	h.deleteAccount(t, fresh.ID)
	h.deleteAccount(t, stale.ID)
	h.ageDeletion(t, stale.ID, h.account.RestoreWindow+time.Hour)

	purged, err := h.repo.PurgeDeletedUsers(t.Context(), time.Now().Add(-h.account.RestoreWindow))
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged = %d, want 1", purged)
	}

	// Свежеудалённый по-прежнему восстановим.
	if _, err := h.auth.RestoreAccount(t.Context(), "purge-fresh@example.com", testPassword); err != nil {
		t.Fatalf("restore a recently deleted account: %v", err)
	}
	// Просроченный исчез совсем — теперь это просто неизвестный адрес.
	if _, err := h.auth.RestoreAccount(t.Context(), "purge-stale@example.com", testPassword); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("restore a purged account: got %v, want ErrInvalidCredentials", err)
	}
}
