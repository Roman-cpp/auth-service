package service

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/krypton/auth-service/internal/domain/user"
)

// fakeRepo — потокобезопасная реализация user.Repository в памяти.
// Тесты сценариев проверяют логику, а не SQL, поэтому база им не нужна;
// поведение, которое опирается на БД (уникальность живого кода, «ноль строк
// = ErrNotFound»), воспроизведено здесь явно.
type fakeRepo struct {
	mu      sync.Mutex
	seq     int
	users   map[user.UserID]*user.User
	codes   map[string]*user.AuthCode
	refresh map[string]*user.RefreshToken
	// revoked повторяет таблицу token_revocations, которую в базе ведёт триггер.
	revoked  map[user.UserID]int64
	nowFunc  func() time.Time
	issueErr error
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		users:   map[user.UserID]*user.User{},
		codes:   map[string]*user.AuthCode{},
		refresh: map[string]*user.RefreshToken{},
		revoked: map[user.UserID]int64{},
		nowFunc: time.Now,
	}
}

func (f *fakeRepo) now() time.Time { return f.nowFunc() }

func (f *fakeRepo) nextID(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

func (f *fakeRepo) Upsert(_ context.Context, dto user.CreateDTO) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, u := range f.users {
		if u.Email != dto.Email || u.DeletedAt != nil {
			continue
		}
		if u.EmailVerified() {
			return nil, user.ErrEmailTaken
		}
		f.applyCreate(u, dto)
		f.bumpTokenVersion(u)
		u.UpdatedAt = f.now()
		return cloneUser(u), nil
	}

	u := &user.User{
		ID:        f.nextID("user"),
		Email:     dto.Email,
		CreatedAt: f.now(),
		UpdatedAt: f.now(),
	}
	f.applyCreate(u, dto)
	f.users[u.ID] = u
	return cloneUser(u), nil
}

// applyCreate повторяет DO UPDATE из SQL: перезапись заявки заменяет всё,
// включая роль и флаги.
func (f *fakeRepo) applyCreate(u *user.User, dto user.CreateDTO) {
	u.LastName, u.FirstName, u.Patronymic = dto.LastName, dto.FirstName, dto.Patronymic
	u.PasswordHash = dto.PasswordHash
	u.Role = dto.Role
	if u.Role == "" {
		u.Role = user.RoleUser
	}
	u.EmailVerifiedAt = nil
	if dto.EmailVerified {
		u.EmailVerifiedAt = ptr(f.now())
	}
	u.MustChangePassword = dto.MustChangePassword
	u.CreatedBy = dto.CreatedBy
}

func (f *fakeRepo) GetByID(_ context.Context, id user.UserID) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil {
		return nil, user.ErrNotFound
	}
	return cloneUser(u), nil
}

func (f *fakeRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, u := range f.users {
		if u.Email == email && u.DeletedAt == nil {
			return cloneUser(u), nil
		}
	}
	return nil, user.ErrNotFound
}

// GetDeletedByEmail повторяет ORDER BY deleted_at DESC: удалённых строк на
// один адрес может быть несколько.
func (f *fakeRepo) GetDeletedByEmail(_ context.Context, email string) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var latest *user.User
	for _, u := range f.users {
		if u.Email != email || u.DeletedAt == nil {
			continue
		}
		if latest == nil || u.DeletedAt.After(*latest.DeletedAt) {
			latest = u
		}
	}
	if latest == nil {
		return nil, user.ErrNotFound
	}
	return cloneUser(latest), nil
}

func (f *fakeRepo) SoftDelete(_ context.Context, id user.UserID) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil {
		return time.Time{}, user.ErrNotFound
	}
	deleted := f.now()
	u.DeletedAt = &deleted
	f.bumpTokenVersion(u)
	return deleted, nil
}

// Restore воспроизводит и частичный уникальный индекс (живой аккаунт с этим
// адресом блокирует возврат), и снос неподтверждённой чужой заявки.
func (f *fakeRepo) Restore(_ context.Context, id user.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt == nil {
		return user.ErrNotFound
	}

	for otherID, other := range f.users {
		if otherID == id || other.Email != u.Email || other.DeletedAt != nil {
			continue
		}
		if other.EmailVerified() {
			return user.ErrEmailTaken
		}
		delete(f.users, otherID)
	}

	u.DeletedAt = nil
	f.bumpTokenVersion(u)
	u.UpdatedAt = f.now()
	return nil
}

// PurgeDeletedUsers физически удаляет строку, а вместе с ней — коды и
// refresh-токены: в схеме это ON DELETE CASCADE.
func (f *fakeRepo) PurgeDeletedUsers(_ context.Context, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var purged int64
	for id, u := range f.users {
		if u.DeletedAt == nil || !u.DeletedAt.Before(before) {
			continue
		}
		// Как триггер на DELETE: токены физически удалённого отозваны.
		f.revoked[id] = u.TokenVersion + 1
		delete(f.users, id)
		purged++

		for codeID, c := range f.codes {
			if c.UserID == id {
				delete(f.codes, codeID)
			}
		}
		for hash, rt := range f.refresh {
			if rt.UserID == id {
				delete(f.refresh, hash)
			}
		}
	}
	return purged, nil
}

func (f *fakeRepo) MarkEmailVerified(_ context.Context, id user.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil || u.EmailVerified() {
		return user.ErrNotFound
	}
	verified := f.now()
	u.EmailVerifiedAt = &verified
	return nil
}

func (f *fakeRepo) UpdatePassword(_ context.Context, id user.UserID, passwordHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil {
		return user.ErrNotFound
	}
	u.PasswordHash = passwordHash
	f.bumpTokenVersion(u)
	u.MustChangePassword = false
	u.UpdatedAt = f.now()
	return nil
}

// ListUsers: поиск подстрокой без учёта регистра, свежие сначала — как
// ORDER BY created_at DESC, id в SQL.
func (f *fakeRepo) ListUsers(_ context.Context, flt user.ListUsersFilter) ([]*user.User, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q := strings.ToLower(flt.Query)
	var matched []*user.User
	for _, u := range f.users {
		if u.DeletedAt != nil {
			continue
		}
		name := strings.ToLower(strings.Join([]string{u.LastName, u.FirstName, deref(u.Patronymic)}, " "))
		if strings.Contains(strings.ToLower(u.Email), q) || strings.Contains(name, q) {
			matched = append(matched, cloneUser(u))
		}
	}
	slices.SortFunc(matched, func(a, b *user.User) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})

	total := len(matched)
	start := min(flt.Offset, total)
	end := min(start+flt.Limit, total)
	return matched[start:end], total, nil
}

func (f *fakeRepo) PromoteModerators(_ context.Context, emails []string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var n int64
	for _, u := range f.users {
		if u.DeletedAt == nil && u.Role != user.RoleModerator && slices.Contains(emails, u.Email) {
			u.Role = user.RoleModerator
			f.bumpTokenVersion(u)
			n++
		}
	}
	return n, nil
}

// bumpTokenVersion повторяет триггеры users_bump_token_version и
// users_record_token_revocation. Вызывается под f.mu.
func (f *fakeRepo) bumpTokenVersion(u *user.User) {
	u.TokenVersion++
	f.revoked[u.ID] = u.TokenVersion
}

func (f *fakeRepo) TokenRevocations(context.Context) (map[user.UserID]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.revoked), nil
}

// Моментов изменения фейк не хранит: уборку записей тесты не проверяют.
func (f *fakeRepo) DeleteStaleTokenRevocations(context.Context, time.Time) error {
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (f *fakeRepo) SetTwoFactorEnabled(_ context.Context, id user.UserID, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil || u.TwoFactorEnabled == enabled {
		return user.ErrNotFound
	}
	u.TwoFactorEnabled = enabled
	return nil
}

func (f *fakeRepo) IssueAuthCode(
	_ context.Context,
	userID user.UserID,
	purpose user.CodePurpose,
	codeHash string,
	expiresAt time.Time,
) (*user.AuthCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.issueErr != nil {
		return nil, f.issueErr
	}

	// Повторяем поведение уникального частичного индекса: живой код на пару
	// (пользователь, назначение) может быть только один.
	for _, c := range f.codes {
		if c.UserID == userID && c.Purpose == purpose && !c.Consumed() {
			consumed := f.now()
			c.ConsumedAt = &consumed
		}
	}

	code := &user.AuthCode{
		ID:        f.nextID("code"),
		UserID:    userID,
		Purpose:   purpose,
		CodeHash:  codeHash,
		ExpiresAt: expiresAt,
		CreatedAt: f.now(),
	}
	f.codes[code.ID] = code
	return cloneCode(code), nil
}

func (f *fakeRepo) LatestAuthCode(_ context.Context, userID user.UserID, purpose user.CodePurpose) (*user.AuthCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var latest *user.AuthCode
	for _, c := range f.codes {
		if c.UserID != userID || c.Purpose != purpose {
			continue
		}
		if latest == nil || c.CreatedAt.After(latest.CreatedAt) {
			latest = c
		}
	}
	if latest == nil {
		return nil, user.ErrNotFound
	}
	return cloneCode(latest), nil
}

func (f *fakeRepo) IncrementAuthCodeAttempts(_ context.Context, id string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.codes[id]
	if !ok {
		return 0, user.ErrNotFound
	}
	c.Attempts++
	return c.Attempts, nil
}

func (f *fakeRepo) ConsumeAuthCode(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.codes[id]
	if !ok || c.Consumed() {
		return user.ErrNotFound
	}
	consumed := f.now()
	c.ConsumedAt = &consumed
	return nil
}

func (f *fakeRepo) DeleteExpiredAuthCodes(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for id, c := range f.codes {
		if c.ExpiresAt.Before(f.now()) {
			delete(f.codes, id)
		}
	}
	return nil
}

func (f *fakeRepo) SaveRefreshToken(_ context.Context, userID user.UserID, tokenHash string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.refresh[tokenHash] = &user.RefreshToken{
		ID:        f.nextID("rt"),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: f.now(),
	}
	return nil
}

func (f *fakeRepo) GetRefreshToken(_ context.Context, tokenHash string) (*user.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rt, ok := f.refresh[tokenHash]
	if !ok {
		return nil, user.ErrNotFound
	}
	clone := *rt
	return &clone, nil
}

func (f *fakeRepo) RevokeRefreshToken(_ context.Context, tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	rt, ok := f.refresh[tokenHash]
	if !ok || rt.RevokedAt != nil {
		return user.ErrNotFound
	}
	revoked := f.now()
	rt.RevokedAt = &revoked
	return nil
}

func (f *fakeRepo) DeleteRefreshToken(_ context.Context, tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.refresh, tokenHash)
	return nil
}

func (f *fakeRepo) DeleteAllRefreshTokens(_ context.Context, userID user.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for hash, rt := range f.refresh {
		if rt.UserID == userID {
			delete(f.refresh, hash)
		}
	}
	return nil
}

func (f *fakeRepo) DeleteExpiredRefreshTokens(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for hash, rt := range f.refresh {
		if rt.ExpiresAt.Before(f.now()) {
			delete(f.refresh, hash)
		}
	}
	return nil
}

// Копии наружу: иначе тест случайно поправит состояние «базы» через
// возвращённый указатель, чего настоящий репозиторий не позволяет.
func cloneUser(u *user.User) *user.User {
	clone := *u
	return &clone
}

func cloneCode(c *user.AuthCode) *user.AuthCode {
	clone := *c
	return &clone
}

// Проверка на этапе компиляции: фейк обязан покрывать весь интерфейс.
var _ user.Repository = (*fakeRepo)(nil)
