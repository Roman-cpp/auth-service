package qrlogin_test

import (
	"errors"
	"testing"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

func start(t *testing.T, h *servicetest.Harness) *auth.QRLoginStart {
	t.Helper()

	s, err := h.QR.Start(t.Context(), "203.0.113.7", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0")
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	return s
}

func TestQRLoginFullFlow(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-flow@example.com")
	s := start(t, h)

	requester, err := h.QR.Scan(t.Context(), s.ID, phone.ID)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if requester.IP != "203.0.113.7" || requester.UserAgent == "" {
		t.Fatalf("requester is not shown to the phone: %+v", requester)
	}

	if err := h.QR.Approve(t.Context(), s.ID, phone.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	session, err := h.QR.Complete(t.Context(), s.Secret)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if session.Tokens == nil || session.Tokens.AccessToken == "" {
		t.Fatal("expected a token pair")
	}
	if session.User.ID != phone.ID {
		t.Fatalf("session opened for %s, want %s", session.User.ID, phone.ID)
	}
}

// Одна заявка — одна сессия: повторное предъявление секрета (утёкшая кука,
// двойной клик) новой сессии не даёт.
func TestQRLoginCompletesOnce(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-once@example.com")
	s := start(t, h)
	mustScanApprove(t, h, s.ID, phone.ID)

	if _, err := h.QR.Complete(t.Context(), s.Secret); err != nil {
		t.Fatalf("first complete: %v", err)
	}
	if _, err := h.QR.Complete(t.Context(), s.Secret); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("second complete: got %v, want ErrQRLoginExpired", err)
	}
}

func TestQRLoginCompleteRequiresApproval(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-noapprove@example.com")
	s := start(t, h)

	if _, err := h.QR.Complete(t.Context(), s.Secret); !errors.Is(err, auth.ErrQRLoginState) {
		t.Fatalf("complete before scan: got %v, want ErrQRLoginState", err)
	}

	if _, err := h.QR.Scan(t.Context(), s.ID, phone.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	// Одно сканирование ещё не согласие: пользователь должен сначала увидеть,
	// чей компьютер просит вход.
	if _, err := h.QR.Complete(t.Context(), s.Secret); !errors.Is(err, auth.ErrQRLoginState) {
		t.Fatalf("complete after scan: got %v, want ErrQRLoginState", err)
	}
}

// Id из QR видят все, кто видит экран. Сессию по нему получить нельзя —
// только по секрету из куки компьютера.
func TestQRLoginIDIsNotASecret(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-id@example.com")
	s := start(t, h)
	mustScanApprove(t, h, s.ID, phone.ID)

	if _, err := h.QR.Complete(t.Context(), s.ID); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("complete with id as secret: got %v, want ErrQRLoginExpired", err)
	}
}

// После сканирования заявка принадлежит отсканировавшему: второй телефон не
// может ни перехватить её, ни подтвердить за первого.
func TestQRLoginBoundToScanner(t *testing.T) {
	h := servicetest.New(t)
	owner := h.RegisterVerified(t, "qr-owner@example.com")
	other := h.RegisterVerified(t, "qr-other@example.com")
	s := start(t, h)

	if _, err := h.QR.Scan(t.Context(), s.ID, owner.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if _, err := h.QR.Scan(t.Context(), s.ID, other.ID); !errors.Is(err, auth.ErrQRLoginState) {
		t.Fatalf("scan by other: got %v, want ErrQRLoginState", err)
	}
	if err := h.QR.Approve(t.Context(), s.ID, other.ID); !errors.Is(err, auth.ErrQRLoginState) {
		t.Fatalf("approve by other: got %v, want ErrQRLoginState", err)
	}
	if err := h.QR.Reject(t.Context(), s.ID, other.ID); !errors.Is(err, auth.ErrQRLoginState) {
		t.Fatalf("reject by other: got %v, want ErrQRLoginState", err)
	}

	// Перезагрузка страницы подтверждения на своём телефоне — не ошибка.
	if _, err := h.QR.Scan(t.Context(), s.ID, owner.ID); err != nil {
		t.Fatalf("rescan by owner: %v", err)
	}
}

func TestQRLoginRejected(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-reject@example.com")
	s := start(t, h)

	if _, err := h.QR.Scan(t.Context(), s.ID, phone.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := h.QR.Reject(t.Context(), s.ID, phone.ID); err != nil {
		t.Fatalf("reject: %v", err)
	}

	if err := h.QR.Approve(t.Context(), s.ID, phone.ID); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("approve after reject: got %v, want ErrQRLoginExpired", err)
	}
	if _, err := h.QR.Complete(t.Context(), s.Secret); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("complete after reject: got %v, want ErrQRLoginExpired", err)
	}
}

func TestQRLoginExpired(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-expired@example.com")
	s := start(t, h)
	h.ExpireQRLogin(t, s.ID)

	if _, err := h.QR.Scan(t.Context(), s.ID, phone.ID); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("scan expired: got %v, want ErrQRLoginExpired", err)
	}
}

func TestQRLoginUnknownID(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-unknown@example.com")

	if _, err := h.QR.Scan(t.Context(), "no-such-id", phone.ID); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("scan unknown: got %v, want ErrQRLoginExpired", err)
	}
}

// Второй фактор повторно не спрашивается: вход подтвердила сессия, которая
// сама открывалась с ним.
func TestQRLoginSkipsSecondFactor(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-2fa@example.com")
	h.EnableTwoFactor(t, phone)
	mailsBefore := h.Mails.Count()

	s := start(t, h)
	mustScanApprove(t, h, s.ID, phone.ID)

	session, err := h.QR.Complete(t.Context(), s.Secret)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if session.Tokens == nil {
		t.Fatal("expected a session without a second-factor code")
	}
	if h.Mails.Count() != mailsBefore {
		t.Fatal("QR login sent a second-factor email")
	}
}

// Аккаунт удалили, пока компьютер забирал сессию, — сессии быть не должно.
func TestQRLoginDeletedAccount(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-deleted@example.com")
	s := start(t, h)
	mustScanApprove(t, h, s.ID, phone.ID)
	h.DeleteAccount(t, phone.ID)

	if _, err := h.QR.Complete(t.Context(), s.Secret); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("complete for deleted account: got %v, want ErrQRLoginExpired", err)
	}
}

func TestQRLoginWatch(t *testing.T) {
	h := servicetest.New(t)
	phone := h.RegisterVerified(t, "qr-watch@example.com")
	s := start(t, h)

	statuses, err := h.QR.Watch(t.Context(), s.ID, s.Secret)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	expectStatus(t, statuses, auth.QRLoginPending)

	if _, err := h.QR.Scan(t.Context(), s.ID, phone.ID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	expectStatus(t, statuses, auth.QRLoginScanned)

	if err := h.QR.Approve(t.Context(), s.ID, phone.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	expectStatus(t, statuses, auth.QRLoginApproved)

	// approved — окончательный статус: поток закрывается сам.
	select {
	case st, ok := <-statuses:
		if ok {
			t.Fatalf("unexpected status after approve: %s", st)
		}
	case <-time.After(time.Second):
		t.Fatal("watch did not close after a final status")
	}
}

func TestQRLoginWatchUnknownSecret(t *testing.T) {
	h := servicetest.New(t)

	if _, err := h.QR.Watch(t.Context(), "no-such-id", "no-such-secret"); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("watch unknown: got %v, want ErrQRLoginExpired", err)
	}
}

// Кука от одной заявки, QR на экране — от другой (два start разошлись):
// следить не за той заявкой нельзя, клиент должен завести новую.
func TestQRLoginWatchMismatchedTicket(t *testing.T) {
	h := servicetest.New(t)
	first := start(t, h)
	second := start(t, h)

	if _, err := h.QR.Watch(t.Context(), second.ID, first.Secret); !errors.Is(err, auth.ErrQRLoginExpired) {
		t.Fatalf("watch mismatched: got %v, want ErrQRLoginExpired", err)
	}
}

func mustScanApprove(t *testing.T, h *servicetest.Harness, id, userID string) {
	t.Helper()

	if _, err := h.QR.Scan(t.Context(), id, userID); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := h.QR.Approve(t.Context(), id, userID); err != nil {
		t.Fatalf("approve: %v", err)
	}
}

// expectStatus ждёт меньше pollInterval: изменения на этом же экземпляре
// должны приходить через hub сразу, а не по таймеру.
func expectStatus(t *testing.T, ch <-chan auth.QRLoginStatus, want auth.QRLoginStatus) {
	t.Helper()

	select {
	case got, ok := <-ch:
		if !ok {
			t.Fatalf("watch closed, want %s", want)
		}
		if got != want {
			t.Fatalf("got status %s, want %s", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("no status within a second, want %s", want)
	}
}
