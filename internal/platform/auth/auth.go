// Package auth хранит личность аутентифицированного пользователя в контексте
// запроса. Записывает её только middleware аутентификации (authn) после
// проверки токена; всё остальное — хендлеры, authz — только читает.
//
// Пакет платформенный и о домене не знает: идентификатор — просто строка
// (user.UserID — её псевдоним, так что типы совпадают без приведения).
package auth

import "context"

// Identity — вошедший пользователь, как его описывает проверенный
// access-токен. Почты здесь нет: в токен она больше не кладётся, а кому она
// нужна, тот читает пользователя из базы.
type Identity struct {
	UserID string
	// Role берётся из токена. Устареть она не может: смена роли отзывает
	// все выданные токены пользователя (см. service.RevocationList).
	Role string
}

// contextKey не экспортируется: подложить личность в контекст в обход
// WithIdentity снаружи пакета нельзя.
type contextKey struct{}

// WithIdentity возвращает контекст с личностью пользователя. Вызывать только
// после проверки токена — всё, что лежит здесь, дальше считается доверенным.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

// IdentityFrom достаёт личность целиком. false — запрос не прошёл
// аутентификацию (маршрут без authn или ошибка в цепочке middleware).
func IdentityFrom(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(contextKey{}).(Identity)
	return id, ok
}

// UserIDFrom — частный случай IdentityFrom для самого частого вопроса.
func UserIDFrom(ctx context.Context) (string, bool) {
	id, ok := IdentityFrom(ctx)
	return id.UserID, ok
}

func RoleFrom(ctx context.Context) (string, bool) {
	id, ok := IdentityFrom(ctx)
	return id.Role, ok
}
