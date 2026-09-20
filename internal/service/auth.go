package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/mailer"
	"golang.org/x/crypto/bcrypt"
)

const passwordBcryptCost = 12

// dummyPasswordHash выравнивает время ответа для несуществующих аккаунтов.
// Без него /auth/login отвечает заметно быстрее, когда почты нет в базе,
// и по одному только таймингу перебирается список зарегистрированных адресов.
// Считается лениво и один раз: bcrypt cost 12 — это ~0.3 с.
var dummyPasswordHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("nexus-timing-equalizer"), passwordBcryptCost)
	if err != nil {
		// Невозможно при валидном cost; паника здесь честнее тихого
		// отключения защиты от тайминг-атаки.
		panic("bcrypt: cannot build dummy hash: " + err.Error())
	}
	return hash
})

type AuthService struct {
	repo   user.Repository
	tokens *TokenIssuer
	codes  *CodeService
}

func NewAuthService(repo user.Repository, tokens *TokenIssuer, codes *CodeService) *AuthService {
	return &AuthService{repo: repo, tokens: tokens, codes: codes}
}

// ---- регистрация и подтверждение почты ----

// Register заводит пользователя без права входа и отправляет код на почту.
// Сессия здесь не выдаётся: до подтверждения адреса аккаунтом пользоваться
// нельзя.
func (s *AuthService) Register(ctx context.Context, req *user.Register) (*user.RegisterResult, error) {
	hash, err := hashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	u, err := s.repo.Upsert(ctx, user.CreateDTO{
		LastName:     req.LastName,
		FirstName:    req.FirstName,
		Patronymic:   req.Patronymic,
		Email:        normalizeEmail(req.Email),
		PasswordHash: hash,
	})
	if err != nil {
		return nil, err
	}

	challenge, err := s.codes.Issue(ctx, u, user.CodePurposeEmailVerify, mailer.TemplateEmailVerify)
	if err != nil {
		return nil, err
	}

	return &user.RegisterResult{User: user.NewUserPreview(u), Challenge: challenge}, nil
}

// ResendEmailVerification никогда не сообщает, есть ли такой аккаунт: для
// неизвестного и уже подтверждённого адреса возвращается такой же ответ,
// просто без письма.
func (s *AuthService) ResendEmailVerification(ctx context.Context, email string) (*user.CodeChallenge, error) {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		return s.codes.Challenge(time.Now()), nil
	}
	if err != nil {
		return nil, err
	}
	if u.EmailVerified() {
		return s.codes.Challenge(time.Now()), nil
	}

	return s.codes.Issue(ctx, u, user.CodePurposeEmailVerify, mailer.TemplateEmailVerify)
}

// VerifyEmail подтверждает адрес и сразу открывает сессию — заставлять
// пользователя тут же логиниться ещё раз незачем, оба фактора уже предъявлены.
func (s *AuthService) VerifyEmail(ctx context.Context, req *user.VerifyCode) (*user.SessionResult, error) {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		// Тот же ответ, что и на неверный код: иначе эндпоинт становится
		// способом проверять, зарегистрирован ли адрес.
		return nil, user.ErrCodeInvalid
	}
	if err != nil {
		return nil, err
	}
	if u.EmailVerified() {
		return nil, user.ErrEmailVerified
	}

	if err := s.codes.Verify(ctx, u.ID, user.CodePurposeEmailVerify, req.Code); err != nil {
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
func (s *AuthService) Login(ctx context.Context, req *user.Login) (*user.LoginResult, error) {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		// Хеш всё равно считаем — ради одинакового времени ответа.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(req.Password))
		return nil, user.ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(req.Password)); err != nil {
		return nil, user.ErrInvalidCredentials
	}

	// Проверяется после пароля: иначе по ответу можно было бы узнать, что
	// адрес зарегистрирован, не зная пароля.
	if !u.EmailVerified() {
		return nil, user.ErrEmailNotVerified
	}

	if !u.TwoFactorEnabled {
		tokens, err := s.tokens.IssueSession(ctx, u)
		if err != nil {
			return nil, err
		}
		return &user.LoginResult{User: user.NewUserPreview(u), Tokens: tokens}, nil
	}

	challenge, err := s.codes.Issue(ctx, u, user.CodePurposeMFALogin, mailer.TemplateLoginCode)
	if err != nil {
		return nil, err
	}
	mfaToken, err := s.tokens.IssueMFAToken(u)
	if err != nil {
		return nil, err
	}

	return &user.LoginResult{User: user.NewUserPreview(u), MFAToken: mfaToken, Challenge: challenge}, nil
}

func (s *AuthService) VerifyMFA(ctx context.Context, mfaToken string, code string) (*user.SessionResult, error) {
	u, err := s.userFromMFAToken(ctx, mfaToken)
	if err != nil {
		return nil, err
	}
	if err := s.codes.Verify(ctx, u.ID, user.CodePurposeMFALogin, code); err != nil {
		return nil, err
	}
	return s.session(ctx, u)
}

// ResendMFACode заодно перевыпускает MFA-токен: иначе окно на ввод кода
// закончилось бы раньше самого кода.
func (s *AuthService) ResendMFACode(ctx context.Context, mfaToken string) (string, *user.CodeChallenge, error) {
	u, err := s.userFromMFAToken(ctx, mfaToken)
	if err != nil {
		return "", nil, err
	}

	challenge, err := s.codes.Issue(ctx, u, user.CodePurposeMFALogin, mailer.TemplateLoginCode)
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
func (s *AuthService) StartEnableTwoFactor(ctx context.Context, id user.UserID, password string) (*user.CodeChallenge, error) {
	u, err := s.authenticateByPassword(ctx, id, password)
	if err != nil {
		return nil, err
	}
	if u.TwoFactorEnabled {
		return nil, user.ErrTwoFactorState
	}
	return s.codes.Issue(ctx, u, user.CodePurposeMFAEnable, mailer.TemplateEnableTwoFactor)
}

// ConfirmEnableTwoFactor включает второй фактор только после успешного ввода
// кода — так проверяется, что почта действительно доступна пользователю.
func (s *AuthService) ConfirmEnableTwoFactor(ctx context.Context, id user.UserID, code string) (*user.UserPreview, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := s.codes.Verify(ctx, u.ID, user.CodePurposeMFAEnable, code); err != nil {
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

func (s *AuthService) DisableTwoFactor(ctx context.Context, id user.UserID, password string) (*user.UserPreview, error) {
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

// ---- пароль ----

// StartPasswordReset отправляет код для смены пароля и, как и повторная
// отправка подтверждения, никогда не сообщает, есть ли такой аккаунт: для
// неизвестного адреса возвращается такой же ответ, просто без письма.
//
// Неподтверждённому аккаунту письмо тоже не уходит. Менять там нечего: такая
// заявка перезаписывается повторной регистрацией, а разослать письмо о сбросе
// на чужой, ещё не подтверждённый адрес иначе мог бы кто угодно.
func (s *AuthService) StartPasswordReset(ctx context.Context, email string) (*user.CodeChallenge, error) {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(email))
	if errors.Is(err, user.ErrNotFound) {
		return s.codes.Challenge(time.Now()), nil
	}
	if err != nil {
		return nil, err
	}
	if !u.EmailVerified() {
		return s.codes.Challenge(time.Now()), nil
	}

	return s.codes.Issue(ctx, u, user.CodePurposePasswordReset, mailer.TemplatePasswordReset)
}

// ResetPassword меняет пароль по коду из письма.
//
// Сессия здесь НЕ открывается, хотя код предъявлен, — в отличие от
// VerifyEmail. Код сброса приходит на ту же почту, что и код второго фактора:
// выдай мы сессию, сброс пароля стал бы обходом 2FA для того, кто получил
// доступ к ящику. После смены пароля нужно войти обычным путём, со всеми
// факторами.
func (s *AuthService) ResetPassword(ctx context.Context, req *user.ResetPassword) error {
	u, err := s.repo.GetByEmail(ctx, normalizeEmail(req.Email))
	if errors.Is(err, user.ErrNotFound) {
		// Тот же ответ, что и на неверный код: иначе эндпоинт становится
		// способом проверять, зарегистрирован ли адрес (см. VerifyEmail).
		return user.ErrCodeInvalid
	}
	if err != nil {
		return err
	}
	// Кода для неподтверждённого аккаунта не выдавалось, но проверка стоит
	// явно: без неё путь зависел бы от того, что StartPasswordReset промолчал.
	if !u.EmailVerified() {
		return user.ErrCodeInvalid
	}

	// Код проверяется раньше, чем новый пароль сравнивается с текущим.
	// Иначе порядок обратный: ErrPasswordUnchanged на произвольный пароль
	// без кода — это оракул, по которому пароль подбирается офлайн.
	if err := s.codes.Verify(ctx, u.ID, user.CodePurposePasswordReset, req.Code); err != nil {
		return err
	}

	return s.replacePassword(ctx, u, req.Password)
}

// ChangePassword меняет пароль изнутри сессии. Вместе со всеми остальными
// сессиями гасится и сессия вызывающего клиента, поэтому взамен он сразу
// получает новую пару токенов: для него смена пароля проходит незаметно,
// а прочие устройства разлогиниваются.
func (s *AuthService) ChangePassword(ctx context.Context, id user.UserID, req *user.ChangePassword) (*user.SessionResult, error) {
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
// refresh-токенов.
//
// Отзыв сессий здесь не побочный эффект, а половина смысла операции: пароль
// меняют в том числе потому, что старый утёк, и тот, кто успел войти по
// старому паролю, обязан потерять доступ. Выданные access-токены переживут
// смену — до конца своего TTL (JWT_ACCESS_TTL, по умолчанию 15 минут);
// чтобы гасить и их, нужен deny-list, которого в сервисе пока нет.
func (s *AuthService) replacePassword(ctx context.Context, u *user.User, password string) error {
	// Совпадение с текущим паролем — отказ, а не тихий успех: иначе смена
	// пароля после утечки ничего не меняет, а пользователь считает иначе.
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil {
		return user.ErrPasswordUnchanged
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	if err := s.repo.UpdatePassword(ctx, u.ID, hash); err != nil {
		return err
	}
	u.PasswordHash = hash

	return s.repo.DeleteAllRefreshTokens(ctx, u.ID)
}

// ---- сессии ----

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*user.TokenResponse, error) {
	tokenHash := HashRefreshToken(refreshToken)

	rt, err := s.repo.GetRefreshToken(ctx, tokenHash)
	if errors.Is(err, user.ErrNotFound) {
		return nil, user.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	// Повторное использование уже отозванного токена — признак кражи:
	// отзываем все сессии пользователя.
	if rt.RevokedAt != nil {
		_ = s.repo.DeleteAllRefreshTokens(ctx, rt.UserID)
		return nil, user.ErrInvalidToken
	}

	if time.Now().After(rt.ExpiresAt) {
		_ = s.repo.DeleteRefreshToken(ctx, tokenHash)
		return nil, user.ErrInvalidToken
	}

	u, err := s.repo.GetByID(ctx, rt.UserID)
	if errors.Is(err, user.ErrNotFound) {
		_ = s.repo.DeleteAllRefreshTokens(ctx, rt.UserID)
		return nil, user.ErrInvalidToken
	}
	if err != nil {
		return nil, err
	}

	if err := s.repo.RevokeRefreshToken(ctx, tokenHash); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			// Токен успели отозвать параллельно — тоже reuse.
			_ = s.repo.DeleteAllRefreshTokens(ctx, rt.UserID)
			return nil, user.ErrInvalidToken
		}
		return nil, err
	}

	return s.tokens.IssueSession(ctx, u)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.repo.DeleteRefreshToken(ctx, HashRefreshToken(refreshToken))
}

func (s *AuthService) ValidateAccessToken(token string) (*user.Claims, error) {
	return s.tokens.ParseAccessToken(token)
}

func (s *AuthService) GetByID(ctx context.Context, id user.UserID) (*user.User, error) {
	return s.repo.GetByID(ctx, id)
}

// ---- helpers ----

func (s *AuthService) session(ctx context.Context, u *user.User) (*user.SessionResult, error) {
	tokens, err := s.tokens.IssueSession(ctx, u)
	if err != nil {
		return nil, err
	}
	return &user.SessionResult{User: user.NewUserPreview(u), Tokens: tokens}, nil
}

func (s *AuthService) userFromMFAToken(ctx context.Context, mfaToken string) (*user.User, error) {
	claims, err := s.tokens.ParseMFAToken(mfaToken)
	if err != nil {
		return nil, err
	}
	u, err := s.repo.GetByID(ctx, claims.UserID)
	if errors.Is(err, user.ErrNotFound) {
		return nil, user.ErrInvalidToken
	}
	return u, err
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordBcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func (s *AuthService) authenticateByPassword(ctx context.Context, id user.UserID, password string) (*user.User, error) {
	u, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, user.ErrInvalidCredentials
	}
	return u, nil
}

// normalizeEmail: без него Foo@example.com и foo@example.com становятся
// разными аккаунтами, а уникальный индекс по email их не ловит.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func ptr[T any](v T) *T { return &v }
