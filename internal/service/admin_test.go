package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/krypton/auth-service/internal/domain/user"
)

func (h *harness) admin() *AdminService { return NewAdminService(h.repo) }

func (h *harness) createByModerator(t *testing.T, email string, role user.Role) *user.AdminCreateUserResult {
	t.Helper()
	mod := h.registerVerified(t, "moderator@example.com")
	res, err := h.admin().CreateUser(t.Context(), mod.ID, &user.AdminCreateUser{
		LastName: "Петров", FirstName: "Пётр", Email: email, Role: role,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return res
}

func TestModeratorCreatesUserWithTemporaryPassword(t *testing.T) {
	h := newHarness(t)
	res := h.createByModerator(t, "New@Example.com ", "")

	if res.User.Email != "new@example.com" {
		t.Errorf("email not normalized: %q", res.User.Email)
	}
	if res.User.Role != user.RoleUser {
		t.Errorf("default role = %q, want user", res.User.Role)
	}
	if !res.User.EmailVerified || !res.User.MustChangePassword || res.User.CreatedBy == nil {
		t.Errorf("unexpected flags: %+v", res.User)
	}
	if len(res.TemporaryPassword) != temporaryPasswordLength ||
		strings.Trim(res.TemporaryPassword, temporaryPasswordAlphabet) != "" {
		t.Errorf("bad temporary password %q", res.TemporaryPassword)
	}
	if h.mails.count() != 1 { // только письмо модератору при его регистрации
		t.Errorf("creating a user must not send mail, sent %d", h.mails.count())
	}
}

func TestTemporaryPasswordDoesNotOpenSession(t *testing.T) {
	h := newHarness(t)
	res := h.createByModerator(t, "temp@example.com", "")

	_, err := h.auth.Login(t.Context(), &user.Login{Email: "temp@example.com", Password: res.TemporaryPassword})
	if !errors.Is(err, user.ErrPasswordChangeRequired) {
		t.Fatalf("login with temporary password: got %v, want ErrPasswordChangeRequired", err)
	}

	// Неверный пароль по-прежнему неотличим от неизвестного аккаунта.
	_, err = h.auth.Login(t.Context(), &user.Login{Email: "temp@example.com", Password: "wrong-password"})
	if !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("wrong password: got %v, want ErrInvalidCredentials", err)
	}
}

func TestChangeInitialPasswordOpensSession(t *testing.T) {
	h := newHarness(t)
	res := h.createByModerator(t, "init@example.com", "")

	result, err := h.auth.ChangeInitialPassword(t.Context(), &user.ChangeInitialPassword{
		Email: "init@example.com", Password: res.TemporaryPassword, NewPassword: testPassword,
	})
	if err != nil {
		t.Fatalf("change initial password: %v", err)
	}
	if result.MFARequired() {
		t.Fatal("expected a session, got MFA challenge")
	}

	if _, err := h.auth.Login(t.Context(), &user.Login{Email: "init@example.com", Password: testPassword}); err != nil {
		t.Fatalf("login with own password: %v", err)
	}
	// Временный пароль больше не действует.
	if _, err := h.auth.Login(t.Context(), &user.Login{Email: "init@example.com", Password: res.TemporaryPassword}); !errors.Is(err, user.ErrInvalidCredentials) {
		t.Fatalf("old temporary password: got %v, want ErrInvalidCredentials", err)
	}
	// И повторная «первая смена» невозможна.
	_, err = h.auth.ChangeInitialPassword(t.Context(), &user.ChangeInitialPassword{
		Email: "init@example.com", Password: testPassword, NewPassword: "another-password",
	})
	if !errors.Is(err, user.ErrNoTemporaryPassword) {
		t.Fatalf("second initial change: got %v, want ErrNoTemporaryPassword", err)
	}
}

func TestChangeInitialPasswordRejectsSamePasswordAndWrongCredentials(t *testing.T) {
	h := newHarness(t)
	res := h.createByModerator(t, "same@example.com", "")

	_, err := h.auth.ChangeInitialPassword(t.Context(), &user.ChangeInitialPassword{
		Email: "same@example.com", Password: res.TemporaryPassword, NewPassword: res.TemporaryPassword,
	})
	if !errors.Is(err, user.ErrPasswordUnchanged) {
		t.Fatalf("same password: got %v, want ErrPasswordUnchanged", err)
	}

	for _, req := range []*user.ChangeInitialPassword{
		{Email: "same@example.com", Password: "wrong-password", NewPassword: testPassword},
		{Email: "nobody@example.com", Password: "whatever", NewPassword: testPassword},
	} {
		if _, err := h.auth.ChangeInitialPassword(t.Context(), req); !errors.Is(err, user.ErrInvalidCredentials) {
			t.Errorf("%s: got %v, want ErrInvalidCredentials", req.Email, err)
		}
	}
}

func TestCreateUserDoesNotOverwriteVerifiedAccount(t *testing.T) {
	h := newHarness(t)
	h.registerVerified(t, "taken@example.com")
	mod := h.registerVerified(t, "mod@example.com")

	_, err := h.admin().CreateUser(t.Context(), mod.ID, &user.AdminCreateUser{
		LastName: "X", FirstName: "Y", Email: "taken@example.com",
	})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("got %v, want ErrEmailTaken", err)
	}
}

func TestModeratorRoleComesFromDatabase(t *testing.T) {
	h := newHarness(t)
	u := h.registerVerified(t, "boss@example.com")
	admin := h.admin()

	if ok, _ := admin.IsModerator(t.Context(), u.ID); ok {
		t.Fatal("fresh user must not be a moderator")
	}
	n, err := admin.PromoteModerators(t.Context(), []string{" BOSS@example.com", ""})
	if err != nil || n != 1 {
		t.Fatalf("promote: n=%d err=%v", n, err)
	}
	if ok, _ := admin.IsModerator(t.Context(), u.ID); !ok {
		t.Fatal("promoted user must be a moderator")
	}
	if n, _ := admin.PromoteModerators(t.Context(), []string{"boss@example.com"}); n != 0 {
		t.Errorf("repeated promotion must be a no-op, changed %d", n)
	}
}

func TestListUsersSearchAndPaging(t *testing.T) {
	h := newHarness(t)
	for _, e := range []string{"a@example.com", "b@example.com", "c@other.org"} {
		h.registerVerified(t, e)
	}

	users, total, err := h.admin().ListUsers(t.Context(), user.ListUsersFilter{Query: "EXAMPLE", Limit: 1})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(users) != 1 {
		t.Fatalf("got %d of %d, want 1 of 2", len(users), total)
	}

	_, total, _ = h.admin().ListUsers(t.Context(), user.ListUsersFilter{Limit: 1000})
	if total != 3 {
		t.Fatalf("total without query = %d, want 3", total)
	}
}
