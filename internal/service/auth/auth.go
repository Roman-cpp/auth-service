package auth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/mailer"
	"github.com/krypton/auth-service/internal/platform/passhash"
	"github.com/krypton/auth-service/internal/service/otp"
	"github.com/krypton/auth-service/internal/service/token"
	"golang.org/x/crypto/bcrypt"
)

// dummyPasswordHash выравнивает время ответа для несуществующих аккаунтов.
// Без него /auth/login отвечает заметно быстрее, когда почты нет в базе,
// и по одному только таймингу перебирается список зарегистрированных адресов.
// Считается лениво и один раз: bcrypt cost 12 — это ~0.3 с.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("nexus-timing-equalizer"), passhash.Cost)
	if err != nil {
		// Невозможно при валидном cost; паника здесь честнее тихого
		// отключения защиты от тайминг-атаки.
		panic("bcrypt: cannot build dummy hash: " + err.Error())
	}
	return hash
})

type Service struct {
	repo        user.Repository
	sessions    auth.Repository
	tokens      *token.Issuer
	codes       *otp.Service
	revocations RevocationSyncer
	account     config.AccountConfig
}

// RevocationSyncer — операции, отзывающие токены (смена пароля, удаление),
// дёргают Sync, чтобы отзыв на этом экземпляре действовал сразу, а не
// к следующему тику фоновой синхронизации.
type RevocationSyncer interface {
	Sync(ctx context.Context) error
}

func NewService(
	repo user.Repository,
	sessions auth.Repository,
	tokens *token.Issuer,
	codes *otp.Service,
	revocations RevocationSyncer,
	account config.AccountConfig,
) *Service {
	return &Service{repo: repo, sessions: sessions, tokens: tokens, codes: codes, revocations: revocations, account: account}
}

// ---- регистрация и подтверждение почты ----

// Register заводит пользователя без права входа и отправляет код на почту.
// Сессия здесь не выдаётся: до подтверждения адреса аккаунтом пользоваться
// нельзя.
func (s *Service) Register(ctx context.Context, req *auth.Register) (*auth.RegisterResult, error) {
	hash, err := passhash.Hash(req.Password)
	if err != nil {
		return nil, err
	}

	u, err := s.repo.Upsert(ctx, user.CreateDTO{
		LastName:     req.LastName,
		FirstName:    req.FirstName,
		Patronymic:   req.Patronymic,
		Email:        user.NormalizeEmail(req.Email),
		PasswordHash: hash,
	})
	if err != nil {
		return nil, err
	}

	challenge, err := s.codes.Issue(ctx, u, auth.CodePurposeEmailVerify, mailer.TemplateEmailVerify)
	if err != nil {
		return nil, err
	}

	return &auth.RegisterResult{User: user.NewUserPreview(u), Challenge: challenge}, nil
}

// ResendEmailVerification никогда не сообщает, есть ли такой аккаунт: для
// неизвестного и уже подтверждённого адреса возвращается такой же ответ,
// просто без письма.
func (s *Service) ResendEmailVerification(ctx context.Context, email string) (*auth.CodeChallenge, error) {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		return s.codes.Challenge(time.Now()), nil
	}
	if err != nil {
		return nil, err
	}
	if u.EmailVerified() {
		return s.codes.Challenge(time.Now()), nil
	}

	return s.codes.Issue(ctx, u, auth.CodePurposeEmailVerify, mailer.TemplateEmailVerify)
}

// VerifyEmail подтверждает адрес и сразу открывает сессию — заставлять
// пользователя тут же логиниться ещё раз незачем, оба фактора уже предъявлены.
func (s *Service) VerifyEmail(ctx context.Context, req *auth.VerifyCode) (*auth.SessionResult, error) {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		// Тот же ответ, что и на неверный код: иначе эндпоинт становится
		// способом проверять, зарегистрирован ли адрес.
		return nil, auth.ErrCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	if u.EmailVerified() {
		return nil, auth.ErrEmailVerified
	}

	if err := s.codes.Verify(ctx, u.ID, auth.CodePurposeEmailVerify, req.Code); err != nil {
		return nil, err
	}
	if err := s.repo.MarkEmailVerified(ctx, u.ID); err != nil {
		return nil, err
	}
	u.EmailVerifiedAt = ptr(time.Now())

	return s.session(ctx, u)
}

// ---- вход ----

// Login проверяет первый фактор. Если у аккаунта включён второй, сессия не
// выдаётся: клиент получает MFA-токен и код на почту.
func (s *Service) Login(ctx context.Context, req *auth.Login) (*auth.LoginResult, error) {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		// Живого аккаунта нет — но, возможно, есть удалённый и ещё
		// восстановимый. Про него владельцу лучше сказать прямо, иначе про
		// возможность восстановления он не узнает никогда.
		return nil, s.loginOnMissingAccount(ctx, req.Email, req.Password)
	}
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return nil, auth.ErrInvalidCredentials
	}

	// Проверяется после пароля: иначе по ответу можно было бы узнать, что
	// адрес зарегистрирован, не зная пароля.
	if !u.EmailVerified() {
		return nil, auth.ErrEmailNotVerified
	}
	// Тоже после пароля, по той же причине. Временный пароль видел модератор,
	// поэтому сессию по нему не выдаём: сначала владелец задаёт свой.
	if u.MustChangePassword {
		return nil, auth.ErrPasswordChangeRequired
	}

	return s.completeLogin(ctx, u)
}

// completeLogin — вход после проверки пароля: сессия сразу или, если включён
// второй фактор, MFA-токен и код на почту.
func (s *Service) completeLogin(ctx context.Context, u *user.User) (*auth.LoginResult, error) {
	if !u.TwoFactorEnabled {
		tokens, err := s.tokens.IssueSession(ctx, u)
		if err != nil {
			return nil, err
		}
		return &auth.LoginResult{User: user.NewUserPreview(u), Tokens: tokens}, nil
	}

	challenge, err := s.codes.Issue(ctx, u, auth.CodePurposeMFALogin, mailer.TemplateLoginCode)
	if err != nil {
		return nil, err
	}
	mfaToken, err := s.tokens.IssueMFAToken(u)
	if err != nil {
		return nil, err
	}

	return &auth.LoginResult{User: user.NewUserPreview(u), MFAToken: mfaToken, Challenge: challenge}, nil
}

func (s *Service) VerifyMFA(ctx context.Context, mfaToken string, code string) (*auth.SessionResult, error) {
	u, err := s.userFromMFAToken(ctx, mfaToken)
	if err != nil {
		return nil, err
	}
	if err := s.codes.Verify(ctx, u.ID, auth.CodePurposeMFALogin, code); err != nil {
		return nil, err
	}
	return s.session(ctx, u)
}

// ResendMFACode заодно перевыпускает MFA-токен: иначе окно на ввод кода
// закончилось бы раньше самого кода.
func (s *Service) ResendMFACode(ctx context.Context, mfaToken string) (string, *auth.CodeChallenge, error) {
	u, err := s.userFromMFAToken(ctx, mfaToken)
	if err != nil {
		return "", nil, err
	}

	challenge, err := s.codes.Issue(ctx, u, auth.CodePurposeMFALogin, mailer.TemplateLoginCode)
	if err != nil {
		return "", nil, err
	}
	refreshed, err := s.tokens.IssueMFAToken(u)
	if err != nil {
		return "", nil, err
	}
	return refreshed, challenge, nil
}

// ---- управление вторым фактором ----

// StartEnableTwoFactor требует пароль: включать второй фактор не должен уметь
// тот, кто просто перехватил активную сессию.
func (s *Service) StartEnableTwoFactor(ctx context.Context, id user.UserID, password string) (*auth.CodeChallenge, error) {
	u, err := s.authenticateByPassword(ctx, id, password)
	if err != nil {
		return nil, err
	}
	if u.TwoFactorEnabled {
		return nil, user.ErrTwoFactorState
	}
	return s.codes.Issue(ctx, u, auth.CodePurposeMFAEnable, mailer.TemplateEnableTwoFactor)
}

// ConfirmEnableTwoFactor включает второй фактор только после успешного ввода
// кода — так проверяется, что почта действительно доступна пользователю.
func (s *Service) ConfirmEnableTwoFactor(ctx context.Context, id user.UserID, code string) (*user.UserPreview, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.codes.Verify(ctx, u.ID, auth.CodePurposeMFAEnable, code); err != nil {
		return nil, err
	}
	if err := s.repo.SetTwoFactorEnabled(ctx, u.ID, true); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil, user.ErrTwoFactorState
		}
		return nil, err
	}
	u.TwoFactorEnabled = true
	return user.NewUserPreview(u), nil
}

func (s *Service) DisableTwoFactor(ctx context.Context, id user.UserID, password string) (*user.UserPreview, error) {
	u, err := s.authenticateByPassword(ctx, id, password)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetTwoFactorEnabled(ctx, u.ID, false); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return nil, user.ErrTwoFactorState
		}
		return nil, err
	}
	u.TwoFactorEnabled = false
	return user.NewUserPreview(u), nil
}

// ---- удаление и восстановление аккаунта ----

// RestoreAccount возвращает удалённый аккаунт владельцу по email и паролю.
//
// Второй фактор здесь не спрашивается, и это ничего не ослабляет: сессию
// восстановление не выдаёт, а войти потом нужно обычным путём — со вторым
// фактором, если он был включён. Права, которых не давал бы обычный вход,
// операция не открывает.
func (s *Service) RestoreAccount(ctx context.Context, email, password string) (*user.UserPreview, error) {
	u, err := s.repo.GetDeletedByEmail(ctx, user.NormalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		// Удалённого аккаунта нет. Возможно, он жив — владельцу честнее
		// сказать, что восстанавливать нечего, чем «неверный пароль».
		return nil, s.restoreOnMissingAccount(ctx, email, password)
	}
	if err != nil {
		return nil, err
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return nil, auth.ErrInvalidCredentials
	}
	// Срок проверяется после пароля — иначе ответ про истёкшее окно сообщал
	// бы кому угодно, что такой адрес когда-то был зарегистрирован.
	if !s.restorable(u) {
		return nil, user.ErrRestoreExpired
	}

	// ErrEmailTaken здесь означает, что адрес успел занять новый
	// подтверждённый аккаунт: вернуть старый уже некуда.
	if err := s.repo.Restore(ctx, u.ID); err != nil {
		return nil, err
	}
	u.DeletedAt = nil

	return user.NewUserPreview(u), nil
}

// restorable: окно отсчитывается от момента удаления. После него аккаунт
// неотличим от несуществующего, даже если уборщик ещё не дошёл до строки.
func (s *Service) restorable(u *user.User) bool {
	return u.DeletedAt != nil && time.Since(*u.DeletedAt) < s.account.RestoreWindow
}

// loginOnMissingAccount разбирает вход по адресу, за которым нет живого
// аккаунта. Удалённый и ещё восстановимый — единственный случай, когда ответ
// отличается от «неверный email или пароль», и только для предъявившего
// верный пароль.
func (s *Service) loginOnMissingAccount(ctx context.Context, email, password string) error {
	u, err := s.repo.GetDeletedByEmail(ctx, user.NormalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		// Хеш всё равно считаем — ради одинакового времени ответа.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(password))
		return auth.ErrInvalidCredentials
	}
	if err != nil {
		return err
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return auth.ErrInvalidCredentials
	}
	if !s.restorable(u) {
		return auth.ErrInvalidCredentials
	}
	return user.ErrAccountDeleted
}

// restoreOnMissingAccount отвечает на попытку восстановить то, что не
// удалено: живой аккаунт с верным паролем — это ErrAccountNotDeleted, всё
// остальное неотличимо от неверных учётных данных.
func (s *Service) restoreOnMissingAccount(ctx context.Context, email, password string) error {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(password))
		return auth.ErrInvalidCredentials
	}
	if err != nil {
		return err
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return auth.ErrInvalidCredentials
	}
	return user.ErrAccountNotDeleted
}

// ---- пароль ----

// StartPasswordReset отправляет код для смены пароля и, как и повторная
// отправка подтверждения, никогда не сообщает, есть ли такой аккаунт: для
// неизвестного адреса возвращается такой же ответ, просто без письма.
//
// Неподтверждённому аккаунту письмо тоже не уходит. Менять там нечего: такая
// заявка перезаписывается повторной регистрацией, а разослать письмо о сбросе
// на чужой, ещё не подтверждённый адрес иначе мог бы кто угодно.
func (s *Service) StartPasswordReset(ctx context.Context, email string) (*auth.CodeChallenge, error) {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		return s.codes.Challenge(time.Now()), nil
	}
	if err != nil {
		return nil, err
	}
	if !u.EmailVerified() {
		return s.codes.Challenge(time.Now()), nil
	}

	return s.codes.Issue(ctx, u, auth.CodePurposePasswordReset, mailer.TemplatePasswordReset)
}

// ResetPassword меняет пароль по коду из письма.
//
// Сессия здесь НЕ открывается, хотя код предъявлен, — в отличие от
// VerifyEmail. Код сброса приходит на ту же почту, что и код второго фактора:
// выдай мы сессию, сброс пароля стал бы обходом 2FA для того, кто получил
// доступ к ящику. После смены пароля нужно войти обычным путём, со всеми
// факторами.
func (s *Service) ResetPassword(ctx context.Context, req *auth.ResetPassword) error {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		// Тот же ответ, что и на неверный код: иначе эндпоинт становится
		// способом проверять, зарегистрирован ли адрес (см. VerifyEmail).
		return auth.ErrCodeInvalid
	}
	if err != nil {
		return err
	}
	// Кода для неподтверждённого аккаунта не выдавалось, но проверка стоит
	// явно: без неё путь зависел бы от того, что StartPasswordReset промолчал.
	if !u.EmailVerified() {
		return auth.ErrCodeInvalid
	}

	// Код проверяется раньше, чем новый пароль сравнивается с текущим.
	// Иначе порядок обратный: ErrPasswordUnchanged на произвольный пароль
	// без кода — это оракул, по которому пароль подбирается офлайн.
	// Сравнение при этом идёт до погашения кода: совпавший пароль — ошибка
	// пользователя, и исправлять её он должен тем же кодом, а не новым письмом.
	sameAsCurrent := func() error {
		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) == nil {
			return auth.ErrPasswordUnchanged
		}
		return nil
	}
	if err := s.codes.VerifyThen(ctx, u.ID, auth.CodePurposePasswordReset, req.Code, sameAsCurrent); err != nil {
		return err
	}

	return s.replacePassword(ctx, u, req.Password)
}

// ChangeInitialPassword заменяет временный пароль, выданный модератором,
// на собственный пароль владельца и сразу продолжает вход — ровно так, как
// его продолжил бы Login: сессия или, если включён, второй фактор.
//
// Ответы для чужого и неизвестного адреса те же, что у Login: эндпоинт не
// должен становиться способом проверять, зарегистрирован ли адрес.
func (s *Service) ChangeInitialPassword(ctx context.Context, req *auth.ChangeInitialPassword) (*auth.LoginResult, error) {
	u, err := s.repo.GetByEmail(ctx, user.NormalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(req.Password))
		return nil, auth.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)) != nil {
		return nil, auth.ErrInvalidCredentials
	}
	if !u.MustChangePassword {
		return nil, auth.ErrNoTemporaryPassword
	}

	if err := s.replacePassword(ctx, u, req.NewPassword); err != nil {
		return nil, err
	}
	u.MustChangePassword = false

	return s.completeLogin(ctx, u)
}

// ChangePassword меняет пароль изнутри сессии. Вместе со всеми остальными
// сессиями гасится и сессия вызывающего клиента, поэтому взамен он сразу
// получает новую пару токенов: для него смена пароля проходит незаметно,
// а прочие устройства разлогиниваются.
func (s *Service) ChangePassword(ctx context.Context, id user.UserID, req *auth.ChangePassword) (*auth.SessionResult, error) {
	u, err := s.authenticateByPassword(ctx, id, req.CurrentPassword)
	if err != nil {
		return nil, err
	}
	if err := s.replacePassword(ctx, u, req.NewPassword); err != nil {
		return nil, err
	}
	return s.session(ctx, u)
}

// replacePassword — общая часть сброса и смены: новый хеш и отзыв всех
// сессий пользователя.
//
// Отзыв сессий здесь не побочный эффект, а половина смысла операции: пароль
// меняют в том числе потому, что старый утёк, и тот, кто успел войти по
// старому паролю, обязан потерять доступ. Refresh-токены удаляются, а уже
// выданные access-токены отзываются сразу: смена пароля поднимает их версию
// (триггер в базе), и revocation.List перестаёт их принимать.
func (s *Service) replacePassword(ctx context.Context, u *user.User, password string) error {
	// Совпадение с текущим паролем — отказ, а не тихий успех: иначе смена
	// пароля после утечки ничего не меняет, а пользователь считает иначе.
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil {
		return auth.ErrPasswordUnchanged
	}

	hash, err := passhash.Hash(password)
	if err != nil {
		return err
	}
	if err := s.repo.UpdatePassword(ctx, u.ID, hash); err != nil {
		return err
	}
	if err := s.sessions.DeleteAllRefreshTokens(ctx, u.ID); err != nil {
		return err
	}

	// Триггер поднял версию токенов — перечитываем пользователя, иначе
	// сессия, которую вызывающий откроет следом, получила бы старую версию
	// и сразу оказалась бы отозванной.
	fresh, err := s.repo.GetByID(ctx, u.ID)
	if err != nil {
		return err
	}
	*u = *fresh

	s.syncRevocations(ctx)
	return nil
}

// syncRevocations: ошибка не прерывает операцию — пароль уже сменён, а
// отзыв догонит фоновая синхронизация через revocation.SyncInterval.
func (s *Service) syncRevocations(ctx context.Context) {
	if err := s.revocations.Sync(ctx); err != nil {
		slog.ErrorContext(ctx, "sync token revocations", slog.Any("error", err))
	}
}

// ---- сессии ----

func (s *Service) Refresh(ctx context.Context, refreshToken string) (*auth.TokenResponse, error) {
	tokenHash := token.HashRefresh(refreshToken)

	rt, err := s.sessions.GetRefreshToken(ctx, tokenHash)
	if errors.Is(err, user.ErrNotFound) {
		return nil, auth.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	// Повторное использование уже отозванного токена — признак кражи:
	// отзываем все сессии пользователя.
	if rt.RevokedAt != nil {
		_ = s.sessions.DeleteAllRefreshTokens(ctx, rt.UserID)
		return nil, auth.ErrInvalidToken
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.sessions.DeleteRefreshToken(ctx, tokenHash)
		return nil, auth.ErrInvalidToken
	}

	u, err := s.repo.GetByID(ctx, rt.UserID)
	if errors.Is(err, user.ErrNotFound) {
		_ = s.sessions.DeleteAllRefreshTokens(ctx, rt.UserID)
		return nil, auth.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	if err := s.sessions.RevokeRefreshToken(ctx, tokenHash); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			// Токен успели отозвать параллельно — тоже reuse.
			_ = s.sessions.DeleteAllRefreshTokens(ctx, rt.UserID)
			return nil, auth.ErrInvalidToken
		}
		return nil, err
	}

	return s.tokens.IssueSession(ctx, u)
}

func (s *Service) Logout(ctx context.Context, refreshToken string) error {
	return s.sessions.DeleteRefreshToken(ctx, token.HashRefresh(refreshToken))
}

func (s *Service) ValidateAccessToken(token string) (*auth.Claims, error) {
	return s.tokens.ParseAccessToken(token)
}

func (s *Service) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return s.repo.GetByID(ctx, id)
}

// ---- helpers ----

func (s *Service) session(ctx context.Context, u *user.User) (*auth.SessionResult, error) {
	tokens, err := s.tokens.IssueSession(ctx, u)
	if err != nil {
		return nil, err
	}
	return &auth.SessionResult{User: user.NewUserPreview(u), Tokens: tokens}, nil
}

func (s *Service) userFromMFAToken(ctx context.Context, mfaToken string) (*user.User, error) {
	claims, err := s.tokens.ParseMFAToken(mfaToken)
	if err != nil {
		return nil, err
	}
	u, err := s.repo.GetByID(ctx, claims.UserID())
	if errors.Is(err, user.ErrNotFound) {
		return nil, auth.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}
	// Пароль сменили, пока ждали второй фактор, — первый шаг уже не в счёт.
	if claims.TokenVersion != u.TokenVersion {
		return nil, auth.ErrInvalidToken
	}
	return u, nil
}

func (s *Service) authenticateByPassword(ctx context.Context, id user.UserID, password string) (*user.User, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, auth.ErrInvalidCredentials
	}
	return u, nil
}

func ptr[T any](v T) *T { return &v }
