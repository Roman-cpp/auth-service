package servicetest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
)

// FakeRepo — потокобезопасная реализация user.Repository и auth.Repository
// в памяти.
// Тесты сценариев проверяют логику, а не SQL, поэтому база им не нужна;
// поведение, которое опирается на БД (уникальность живого кода, «ноль строк
// = ErrNotFound»), воспроизведено здесь явно.
type FakeRepo struct {
	mu      sync.Mutex
	seq     int
	users   map[user.UserID]*user.User
	codes   map[string]*auth.AuthCode
	refresh map[string]*auth.RefreshToken
	qr      map[string]*auth.QRLogin
	// revoked повторяет таблицу token_revocations, которую в базе ведёт триггер.
	revoked  map[user.UserID]int64
	nowFunc  func() time.Time
	issueErr error
}

func NewFakeRepo() *FakeRepo {
	return &FakeRepo{
		users:   map[user.UserID]*user.User{},
		codes:   map[string]*auth.AuthCode{},
		refresh: map[string]*auth.RefreshToken{},
		qr:      map[string]*auth.QRLogin{},
		revoked: map[user.UserID]int64{},
		nowFunc: time.Now,
	}
}

func (f *FakeRepo) now() time.Time { return f.nowFunc() }

func (f *FakeRepo) nextID(prefix string) string {
	f.seq++
	return fmt.Sprintf("%s-%d", prefix, f.seq)
}

func (f *FakeRepo) Upsert(_ context.Context, dto user.CreateDTO) (*user.User, error) {
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
func (f *FakeRepo) applyCreate(u *user.User, dto user.CreateDTO) {
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

func (f *FakeRepo) GetByID(_ context.Context, id user.UserID) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil {
		return nil, user.ErrNotFound
	}
	return cloneUser(u), nil
}

func (f *FakeRepo) GetByIDWithDeleted(_ context.Context, id user.UserID) (*user.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok {
		return nil, user.ErrNotFound
	}
	return cloneUser(u), nil
}

func (f *FakeRepo) GetByEmail(_ context.Context, email string) (*user.User, error) {
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
func (f *FakeRepo) GetDeletedByEmail(_ context.Context, email string) (*user.User, error) {
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

func (f *FakeRepo) SoftDelete(_ context.Context, id user.UserID) (time.Time, error) {
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
func (f *FakeRepo) Restore(_ context.Context, id user.UserID) error {
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
func (f *FakeRepo) PurgeDeletedUsers(_ context.Context, before time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var purged int64
	for id, u := range f.users {
		if u.DeletedAt == nil || !u.DeletedAt.Before(before) {
			continue
		}
		f.purge(id)
		purged++
	}
	return purged, nil
}

func (f *FakeRepo) HardDelete(_ context.Context, id user.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt == nil {
		return user.ErrNotFound
	}
	f.purge(id)
	return nil
}

// purge — физическое удаление строки с каскадом, как ON DELETE CASCADE в
// схеме. Вызывается под f.mu.
func (f *FakeRepo) purge(id user.UserID) {
	// Как триггер на DELETE: токены физически удалённого отозваны.
	f.revoked[id] = f.users[id].TokenVersion + 1
	delete(f.users, id)

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
	for qrID, q := range f.qr {
		if q.UserID != nil && *q.UserID == id {
			delete(f.qr, qrID)
		}
	}
}

func (f *FakeRepo) MarkEmailVerified(_ context.Context, id user.UserID) error {
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

func (f *FakeRepo) UpdatePassword(_ context.Context, id user.UserID, passwordHash string) error {
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
// ORDER BY created_at DESC, id в SQL (у удалённых — по deleted_at).
func (f *FakeRepo) ListUsers(_ context.Context, flt user.ListUsersFilter) ([]*user.User, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q := strings.ToLower(flt.Query)
	var matched []*user.User
	for _, u := range f.users {
		if (u.DeletedAt != nil) != flt.Deleted {
			continue
		}
		name := strings.ToLower(strings.Join([]string{u.LastName, u.FirstName, deref(u.Patronymic)}, " "))
		if strings.Contains(strings.ToLower(u.Email), q) || strings.Contains(name, q) {
			matched = append(matched, cloneUser(u))
		}
	}
	slices.SortFunc(matched, func(a, b *user.User) int {
		if flt.Deleted {
			if c := b.DeletedAt.Compare(*a.DeletedAt); c != 0 {
				return c
			}
		} else if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})

	total := len(matched)
	start := min(flt.Offset, total)
	end := min(start+flt.Limit, total)
	return matched[start:end], total, nil
}

func (f *FakeRepo) PromoteModerators(_ context.Context, emails []string) (int64, error) {
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
func (f *FakeRepo) bumpTokenVersion(u *user.User) {
	u.TokenVersion++
	f.revoked[u.ID] = u.TokenVersion
}

func (f *FakeRepo) TokenRevocations(context.Context) (map[user.UserID]int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return maps.Clone(f.revoked), nil
}

// Моментов изменения фейк не хранит: уборку записей тесты не проверяют.
func (f *FakeRepo) DeleteStaleTokenRevocations(context.Context, time.Time) error {
	return nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (f *FakeRepo) SetTwoFactorEnabled(_ context.Context, id user.UserID, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.users[id]
	if !ok || u.DeletedAt != nil || u.TwoFactorEnabled == enabled {
		return user.ErrNotFound
	}
	u.TwoFactorEnabled = enabled
	return nil
}

func (f *FakeRepo) IssueAuthCode(
	_ context.Context,
	userID user.UserID,
	purpose auth.CodePurpose,
	codeHash string,
	expiresAt time.Time,
) (*auth.AuthCode, error) {
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

	code := &auth.AuthCode{
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

func (f *FakeRepo) LatestAuthCode(_ context.Context, userID user.UserID, purpose auth.CodePurpose) (*auth.AuthCode, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	var latest *auth.AuthCode
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

func (f *FakeRepo) IncrementAuthCodeAttempts(_ context.Context, id string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	c, ok := f.codes[id]
	if !ok {
		return 0, user.ErrNotFound
	}
	c.Attempts++
	return c.Attempts, nil
}

func (f *FakeRepo) ConsumeAuthCode(_ context.Context, id string) error {
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

func (f *FakeRepo) DeleteExpiredAuthCodes(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for id, c := range f.codes {
		if c.ExpiresAt.Before(f.now()) {
			delete(f.codes, id)
		}
	}
	return nil
}

func (f *FakeRepo) SaveRefreshToken(_ context.Context, userID user.UserID, tokenHash string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.refresh[tokenHash] = &auth.RefreshToken{
		ID:        f.nextID("rt"),
		UserID:    userID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: f.now(),
	}
	return nil
}

func (f *FakeRepo) GetRefreshToken(_ context.Context, tokenHash string) (*auth.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	rt, ok := f.refresh[tokenHash]
	if !ok {
		return nil, user.ErrNotFound
	}
	clone := *rt
	return &clone, nil
}

func (f *FakeRepo) RevokeRefreshToken(_ context.Context, tokenHash string) error {
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

func (f *FakeRepo) DeleteRefreshToken(_ context.Context, tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	delete(f.refresh, tokenHash)
	return nil
}

func (f *FakeRepo) DeleteAllRefreshTokens(_ context.Context, userID user.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for hash, rt := range f.refresh {
		if rt.UserID == userID {
			delete(f.refresh, hash)
		}
	}
	return nil
}

func (f *FakeRepo) DeleteExpiredRefreshTokens(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for hash, rt := range f.refresh {
		if rt.ExpiresAt.Before(f.now()) {
			delete(f.refresh, hash)
		}
	}
	return nil
}

func (f *FakeRepo) CreateQRLogin(_ context.Context, secretHash, ip, userAgent string, expiresAt time.Time) (*auth.QRLogin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q := &auth.QRLogin{
		ID:          f.nextID("qr"),
		SecretHash:  secretHash,
		Status:      auth.QRLoginPending,
		RequesterIP: ip,
		RequesterUA: userAgent,
		ExpiresAt:   expiresAt,
		CreatedAt:   f.now(),
	}
	f.qr[q.ID] = q
	return cloneQR(q), nil
}

func (f *FakeRepo) GetQRLogin(_ context.Context, id string) (*auth.QRLogin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q, ok := f.qr[id]
	if !ok {
		return nil, user.ErrNotFound
	}
	return cloneQR(q), nil
}

func (f *FakeRepo) GetQRLoginBySecret(_ context.Context, secretHash string) (*auth.QRLogin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if q := f.qrBySecret(secretHash); q != nil {
		return cloneQR(q), nil
	}
	return nil, user.ErrNotFound
}

func (f *FakeRepo) ScanQRLogin(_ context.Context, id string, userID user.UserID) (*auth.QRLogin, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q, ok := f.qr[id]
	if !ok || q.Expired(f.now()) {
		return nil, user.ErrNotFound
	}
	rescan := q.Status == auth.QRLoginScanned && q.UserID != nil && *q.UserID == userID
	if q.Status != auth.QRLoginPending && !rescan {
		return nil, user.ErrNotFound
	}
	q.Status = auth.QRLoginScanned
	q.UserID = &userID
	return cloneQR(q), nil
}

func (f *FakeRepo) ApproveQRLogin(_ context.Context, id string, userID user.UserID, completeBy time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	q, ok := f.qr[id]
	if !ok || !f.scannedBy(q, userID) {
		return user.ErrNotFound
	}
	q.Status = auth.QRLoginApproved
	if completeBy.After(q.ExpiresAt) {
		q.ExpiresAt = completeBy
	}
	return nil
}

func (f *FakeRepo) RejectQRLogin(_ context.Context, id string, userID user.UserID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	q, ok := f.qr[id]
	if !ok || !f.scannedBy(q, userID) {
		return user.ErrNotFound
	}
	q.Status = auth.QRLoginRejected
	return nil
}

func (f *FakeRepo) ConsumeQRLogin(_ context.Context, secretHash string) (user.UserID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	q := f.qrBySecret(secretHash)
	if q == nil || q.Status != auth.QRLoginApproved || q.Expired(f.now()) {
		return "", user.ErrNotFound
	}
	q.Status = auth.QRLoginConsumed
	return *q.UserID, nil
}

func (f *FakeRepo) DeleteExpiredQRLogins(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for id, q := range f.qr {
		if q.Expired(f.now()) {
			delete(f.qr, id)
		}
	}
	return nil
}

// qrBySecret и scannedBy вызываются под f.mu.
func (f *FakeRepo) qrBySecret(secretHash string) *auth.QRLogin {
	for _, q := range f.qr {
		if q.SecretHash == secretHash {
			return q
		}
	}
	return nil
}

func (f *FakeRepo) scannedBy(q *auth.QRLogin, userID user.UserID) bool {
	return q.Status == auth.QRLoginScanned && q.UserID != nil && *q.UserID == userID && !q.Expired(f.now())
}

// Копии наружу: иначе тест случайно поправит состояние «базы» через
// возвращённый указатель, чего настоящий репозиторий не позволяет.
func cloneUser(u *user.User) *user.User {
	clone := *u
	return &clone
}

func cloneCode(c *auth.AuthCode) *auth.AuthCode {
	clone := *c
	return &clone
}

func cloneQR(q *auth.QRLogin) *auth.QRLogin {
	clone := *q
	if q.UserID != nil {
		clone.UserID = ptr(*q.UserID)
	}
	return &clone
}

// Проверка на этапе компиляции: фейк обязан покрывать оба хранилища —
// тестам сценариев не важно, как они разнесены в реальной базе.
var (
	_ user.Repository = (*FakeRepo)(nil)
	_ auth.Repository = (*FakeRepo)(nil)
)

func ptr[T any](v T) *T { return &v }
