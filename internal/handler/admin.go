package handler

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	authctx "github.com/krypton/auth-service/internal/platform/auth"
	"github.com/krypton/auth-service/internal/service/admin"
)

// AdminHandler — ручки админки. Доступ к ним закрыт RequireModerator
// на уровне роутера, поэтому сами обработчики роль не проверяют.
type AdminHandler struct {
	base
	svc *admin.Service
}

func NewAdminHandler(svc *admin.Service, log *slog.Logger) *AdminHandler {
	return &AdminHandler{base: base{log: log}, svc: svc}
}

// ListUsers: ?q=строка&status=active|deleted&limit=50&offset=0.
// Некорректные числа не ошибка — берутся значения по умолчанию, пределы
// задаёт сервис. Неизвестный status — ошибка: молча показать живых вместо
// удалённых значило бы подсунуть модератору не тот список.
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	var deleted bool
	switch q.Get("status") {
	case "", "active":
	case "deleted":
		deleted = true
	default:
		writeError(w, r, apiError{http.StatusBadRequest, "validation_failed", "некорректные поля: status"})
		return
	}

	users, total, err := h.svc.ListUsers(r.Context(), user.ListUsersFilter{
		Query:   q.Get("q"),
		Deleted: deleted,
		Limit:   limit,
		Offset:  offset,
	})
	if err != nil {
		h.fail(w, r, "admin_list_users", err)
		return
	}

	writeData(w, r, http.StatusOK, map[string]any{"users": users, "total": total})
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "admin_create_user", auth.ErrInvalidToken)
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
	writeData(w, r, http.StatusCreated, result)
}

// DeleteUser — логическое удаление, первый шаг.
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "admin_delete_user", auth.ErrInvalidToken)
		return
	}
	id := chi.URLParam(r, "id")

	view, err := h.svc.DeleteUser(r.Context(), actor, id)
	if err != nil {
		h.fail(w, r, "admin_delete_user", err)
		return
	}

	h.log.InfoContext(r.Context(), "user deleted by moderator",
		slog.String("moderator_id", actor), slog.String("user_id", id))
	writeData(w, r, http.StatusOK, map[string]any{"user": view})
}

func (h *AdminHandler) RestoreUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "admin_restore_user", auth.ErrInvalidToken)
		return
	}
	id := chi.URLParam(r, "id")

	view, err := h.svc.RestoreUser(r.Context(), id)
	if err != nil {
		h.fail(w, r, "admin_restore_user", err)
		return
	}

	h.log.InfoContext(r.Context(), "user restored by moderator",
		slog.String("moderator_id", actor), slog.String("user_id", id))
	writeData(w, r, http.StatusOK, map[string]any{"user": view})
}

// PurgeUser — удаление навсегда, второй шаг. Отменить его нельзя.
func (h *AdminHandler) PurgeUser(w http.ResponseWriter, r *http.Request) {
	actor, ok := authctx.UserIDFrom(r.Context())
	if !ok {
		h.fail(w, r, "admin_purge_user", auth.ErrInvalidToken)
		return
	}
	id := chi.URLParam(r, "id")

	if err := h.svc.PurgeUser(r.Context(), actor, id); err != nil {
		h.fail(w, r, "admin_purge_user", err)
		return
	}

	h.log.InfoContext(r.Context(), "user purged by moderator",
		slog.String("moderator_id", actor), slog.String("user_id", id))
	w.WriteHeader(http.StatusNoContent)
}
