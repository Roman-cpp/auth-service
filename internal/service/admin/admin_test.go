package admin

import (
	"errors"
	"strings"
	"testing"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service/servicetest"
)

func admin(h *servicetest.Harness) *Service { return NewService(h.Repo) }

func createByModerator(t *testing.T, h *servicetest.Harness, email string, role user.Role) *user.AdminCreateUserResult {
	t.Helper()
	mod := h.RegisterVerified(t, "moderator@example.com")
	res, err := admin(h).CreateUser(t.Context(), mod.ID, &user.AdminCreateUser{
		LastName: "Петров", FirstName: "Пётр", Email: email, Role: role,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return res
}

func TestModeratorCreatesUserWithTemporaryPassword(t *testing.T) {
	h := servicetest.New(t)
	res := createByModerator(t, h, "New@Example.com ", "")

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
	if h.Mails.Count() != 1 { // только письмо модератору при его регистрации
		t.Errorf("creating a user must not send mail, sent %d", h.Mails.Count())
	}
}

func TestTemporaryPasswordDoesNotOpenSession(t *testing.T) {
	h := servicetest.New(t)
	res := createByModerator(t, h, "temp@example.com", "")

	_, err := h.Auth.Login(t.Context(), &auth.Login{Email: "temp@example.com", Password: res.TemporaryPassword})
	if !errors.Is(err, auth.ErrPasswordChangeRequired) {
		t.Fatalf("login with temporary password: got %v, want ErrPasswordChangeRequired", err)
	}

	// Неверный пароль по-прежнему неотличим от неизвестного аккаунта.
	_, err = h.Auth.Login(t.Context(), &auth.Login{Email: "temp@example.com", Password: "wrong-password"})
	if !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: got %v, want ErrInvalidCredentials", err)
	}
}

func TestChangeInitialPasswordOpensSession(t *testing.T) {
	h := servicetest.New(t)
	res := createByModerator(t, h, "init@example.com", "")

	result, err := h.Auth.ChangeInitialPassword(t.Context(), &auth.ChangeInitialPassword{
		Email: "init@example.com", Password: res.TemporaryPassword, NewPassword: servicetest.Password,
	})
	if err != nil {
		t.Fatalf("change initial password: %v", err)
	}
	if result.MFARequired() {
		t.Fatal("expected a session, got MFA challenge")
	}

	if _, err := h.Auth.Login(t.Context(), &auth.Login{Email: "init@example.com", Password: servicetest.Password}); err != nil {
		t.Fatalf("login with own password: %v", err)
	}
	// Временный пароль больше не действует.
	if _, err := h.Auth.Login(t.Context(), &auth.Login{Email: "init@example.com", Password: res.TemporaryPassword}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old temporary password: got %v, want ErrInvalidCredentials", err)
	}
	// И повторная «первая смена» невозможна.
	_, err = h.Auth.ChangeInitialPassword(t.Context(), &auth.ChangeInitialPassword{
		Email: "init@example.com", Password: servicetest.Password, NewPassword: "another-password",
	})
	if !errors.Is(err, auth.ErrNoTemporaryPassword) {
		t.Fatalf("second initial change: got %v, want ErrNoTemporaryPassword", err)
	}
}

func TestChangeInitialPasswordRejectsSamePasswordAndWrongCredentials(t *testing.T) {
	h := servicetest.New(t)
	res := createByModerator(t, h, "same@example.com", "")

	_, err := h.Auth.ChangeInitialPassword(t.Context(), &auth.ChangeInitialPassword{
		Email: "same@example.com", Password: res.TemporaryPassword, NewPassword: res.TemporaryPassword,
	})
	if !errors.Is(err, auth.ErrPasswordUnchanged) {
		t.Fatalf("same password: got %v, want ErrPasswordUnchanged", err)
	}

	for _, req := range []*auth.ChangeInitialPassword{
		{Email: "same@example.com", Password: "wrong-password", NewPassword: servicetest.Password},
		{Email: "nobody@example.com", Password: "whatever", NewPassword: servicetest.Password},
	} {
		if _, err := h.Auth.ChangeInitialPassword(t.Context(), req); !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Errorf("%s: got %v, want ErrInvalidCredentials", req.Email, err)
		}
	}
}

func TestCreateUserDoesNotOverwriteVerifiedAccount(t *testing.T) {
	h := servicetest.New(t)
	h.RegisterVerified(t, "taken@example.com")
	mod := h.RegisterVerified(t, "mod@example.com")

	_, err := admin(h).CreateUser(t.Context(), mod.ID, &user.AdminCreateUser{
		LastName: "X", FirstName: "Y", Email: "taken@example.com",
	})
	if !errors.Is(err, user.ErrEmailTaken) {
		t.Fatalf("got %v, want ErrEmailTaken", err)
	}
}

func TestPromoteModerators(t *testing.T) {
	h := servicetest.New(t)
	u := h.RegisterVerified(t, "boss@example.com")
	admin := admin(h)

	role := func() user.Role {
		t.Helper()
		got, err := h.Repo.GetByID(t.Context(), u.ID)
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		return got.Role
	}

	if role() != user.RoleUser {
		t.Fatal("fresh user must not be a moderator")
	}
	n, err := admin.PromoteModerators(t.Context(), []string{" BOSS@example.com", ""})
	if err != nil || n != 1 {
		t.Fatalf("promote: n=%d err=%v", n, err)
	}
	if role() != user.RoleModerator {
		t.Fatal("promoted user must be a moderator")
	}
	if n, _ := admin.PromoteModerators(t.Context(), []string{"boss@example.com"}); n != 0 {
		t.Errorf("repeated promotion must be a no-op, changed %d", n)
	}
}

func TestListUsersSearchAndPaging(t *testing.T) {
	h := servicetest.New(t)
	for _, e := range []string{"a@example.com", "b@example.com", "c@other.org"} {
		h.RegisterVerified(t, e)
	}

	users, total, err := admin(h).ListUsers(t.Context(), user.ListUsersFilter{Query: "EXAMPLE", Limit: 1})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(users) != 1 {
		t.Fatalf("got %d of %d, want 1 of 2", len(users), total)
	}

	_, total, _ = admin(h).ListUsers(t.Context(), user.ListUsersFilter{Limit: 1000})
	if total != 3 {
		t.Fatalf("total without query = %d, want 3", total)
	}
}
