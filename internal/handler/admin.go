package handler

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/internal/service"
)

// AdminHandler — ручки админки. Доступ к ним закрыт RequireModerator
// на уровне роутера, поэтому сами обработчики роль не проверяют.
type AdminHandler struct {
	base
	svc *service.AdminService
}

func NewAdminHandler(svc *service.AdminService, log *slog.Logger) *AdminHandler {
	return &AdminHandler{base: base{log: log}, svc: svc}
}

// ListUsers: ?q=строка&limit=50&offset=0. Некорректные числа не ошибка —
// берутся значения по умолчанию, пределы задаёт сервис.
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	users, total, err := h.svc.ListUsers(r.Context(), user.ListUsersFilter{
		Query:  q.Get("q"),
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		h.fail(w, r, "admin_list_users", err)
		return
	}

	writeData(w, http.StatusOK, map[string]any{"users": users, "total": total})
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := auth.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "admin_create_user", user.ErrInvalidToken)
		return
	}

	req, ok := decodeJSON[user.AdminCreateUser](w, r)
	if !ok {
		return
	}

	result, err := h.svc.CreateUser(r.Context(), actor, req)
	if err != nil {
		h.fail(w, r, "admin_create_user", err)
		return
	}

	// Кто кого завёл — в лог: это действие с чужим аккаунтом.
	h.log.InfoContext(r.Context(), "user created by moderator",
		slog.String("moderator_id", actor),
		slog.String("user_id", result.User.ID),
		slog.String("role", string(result.User.Role)),
	)
	writeData(w, http.StatusCreated, result)
}
