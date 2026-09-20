package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/service"
	"github.com/krypton/auth-service/pkg/httputil"
)

// maxRequestBody: тела запросов здесь — короткий JSON, поэтому вход
// ограничен явно, а не дефолтом сервера (его нет).
const maxRequestBody = 64 << 10

var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	// В ошибках должно быть имя поля из JSON, а не имя поля структуры Go:
	// клиенту про Patronymic знать неоткуда.
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
	return v
}

type apiError struct {
	status  int
	code    string
	message string
}

// errorCatalog — единственное место, где доменные ошибки превращаются
// в HTTP-ответы. Раньше каждый обработчик разбирал их сам, и одна и та же
// ошибка в разных местах отвечала по-разному.
var errorCatalog = []struct {
	err error
	api apiError
}{
	{user.ErrEmailTaken, apiError{http.StatusConflict, "email_taken", "этот адрес уже зарегистрирован"}},
	{user.ErrInvalidCredentials, apiError{http.StatusUnauthorized, "invalid_credentials", "неверный email или пароль"}},
	{user.ErrEmailNotVerified, apiError{http.StatusForbidden, "email_not_verified", "адрес почты не подтверждён"}},
	{user.ErrEmailVerified, apiError{http.StatusConflict, "email_already_verified", "адрес почты уже подтверждён"}},
	{user.ErrCodeExpired, apiError{http.StatusBadRequest, "code_expired", "срок действия кода истёк"}},
	{user.ErrCodeAttempts, apiError{http.StatusTooManyRequests, "too_many_attempts", "слишком много неверных попыток, запросите новый код"}},
	{user.ErrCodeInvalid, apiError{http.StatusBadRequest, "invalid_code", "неверный код подтверждения"}},
	{user.ErrInvalidToken, apiError{http.StatusUnauthorized, "invalid_token", "сессия недействительна или истекла"}},
	{user.ErrPasswordUnchanged, apiError{http.StatusBadRequest, "password_unchanged", "новый пароль совпадает с текущим"}},
	{user.ErrTwoFactorState, apiError{http.StatusConflict, "two_factor_state", "двухфакторная аутентификация уже в этом состоянии"}},
	{service.ErrMailDelivery, apiError{http.StatusBadGateway, "mail_delivery_failed", "не удалось отправить письмо, попробуйте позже"}},
	{user.ErrNotFound, apiError{http.StatusNotFound, "not_found", "не найдено"}},
}

// base — общая часть обработчиков: логирование и преобразование ошибок.
type base struct {
	log *slog.Logger
}

func (b base) fail(w http.ResponseWriter, r *http.Request, op string, err error) {
	for _, m := range errorCatalog {
		if errors.Is(err, m.err) {
			// Сбой доставки письма — не вина клиента, его надо видеть в логах.
			if m.api.status >= http.StatusInternalServerError {
				b.log.ErrorContext(r.Context(), "request failed",
					slog.String("op", op), slog.String("code", m.api.code), slog.Any("error", err))
			}
			writeError(w, m.api)
			return
		}
	}

	b.log.ErrorContext(r.Context(), "unhandled error", slog.String("op", op), slog.Any("error", err))
	writeError(w, apiError{http.StatusInternalServerError, "internal_error", "внутренняя ошибка сервера"})
}

func writeError(w http.ResponseWriter, e apiError) {
	httputil.WriteJSON(w, e.status, httputil.ErrorResponse{Code: e.code, Message: e.message})
}

func writeData(w http.ResponseWriter, status int, data any) {
	httputil.WriteJSON(w, status, httputil.Response{Data: data})
}

// decodeJSON читает и валидирует тело запроса. Возвращает false, если ответ
// клиенту уже отправлен.
func decodeJSON[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)

	var req T
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, apiError{http.StatusBadRequest, "bad_request", "не удалось разобрать тело запроса"})
		return nil, false
	}
	if err := validate.Struct(&req); err != nil {
		writeError(w, apiError{http.StatusBadRequest, "validation_failed", validationMessage(err)})
		return nil, false
	}
	return &req, true
}

// validationMessage отдаёт список полей, а не дамп ошибки валидатора:
// в нём видны внутренние имена типов, и читать его клиенту бесполезно.
func validationMessage(err error) string {
	var invalid validator.ValidationErrors
	if !errors.As(err, &invalid) {
		return "запрос не прошёл валидацию"
	}
	fields := make([]string, 0, len(invalid))
	for _, fieldErr := range invalid {
		fields = append(fields, fieldErr.Field())
	}
	return fmt.Sprintf("некорректные поля: %s", strings.Join(fields, ", "))
}
