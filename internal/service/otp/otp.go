package otp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/domain/auth"
	"github.com/krypton/auth-service/internal/domain/user"
	"github.com/krypton/auth-service/internal/mailer"
	"golang.org/x/crypto/bcrypt"
)

const (
	// codeDigits — длина одноразового кода. Шесть цифр это всего 10^6
	// вариантов, поэтому стойкость держится не на энтропии, а на трёх
	// ограничениях: TTL, счётчике попыток и кулдауне на перевыпуск.
	codeDigits = 6
	// Для кода cost ниже, чем для пароля: проверка кода происходит на
	// горячем пути входа, а защищает хеш всего лишь от офлайн-перебора
	// миллиона вариантов в течение TTL.
	codeBcryptCost = 10
)

var codeSpace = big.NewInt(1_000_000)

// ErrMailDelivery отделяет «код выпущен, но письмо не ушло» от прочих
// внутренних ошибок: пользователю про это нужно сказать отдельно, иначе он
// будет ждать письмо, которого не будет.
var ErrMailDelivery = errors.New("cannot deliver email")

// Service выпускает и проверяет одноразовые коды. Все три сценария
// (подтверждение почты, второй фактор входа, включение 2FA) отличаются
// только значением purpose и текстом письма.
type Service struct {
	repo   auth.Repository
	mailer *mailer.Mailer
	cfg    config.CodesConfig
}

func NewService(repo auth.Repository, m *mailer.Mailer, cfg config.CodesConfig) *Service {
	return &Service{repo: repo, mailer: m, cfg: cfg}
}

// Issue выпускает новый код и отправляет его письмом. Предыдущий живой код
// той же пары (пользователь, назначение) гасится — одновременно валидных
// кодов не бывает.
//
// Если предыдущий код выдан меньше кулдауна назад, новый не выпускается:
// возвращаются сроки уже действующего. Это и есть защита от рассылки писем
// на чужой адрес — повторные вызовы просто ничего не отправляют.
//
// Письмо отправляется синхронно: если SMTP недоступен, пользователь должен
// увидеть ошибку сразу, а не ждать письмо, которого не будет.
func (s *Service) Issue(
	ctx context.Context,
	u *user.User,
	purpose auth.CodePurpose,
	tpl mailer.CodeTemplate,
) (*auth.CodeChallenge, error) {
	active, err := s.activeWithinCooldown(ctx, u.ID, purpose)
	if err != nil {
		return nil, err
	}
	// Код уже выдан только что — отдаём его сроки и НЕ шлём второе письмо.
	// Ошибку здесь возвращать нечем: для вызывающего ничего не сломалось,
	// действующий код у пользователя на руках, а кнопка повторной отправки
	// гасится по ResendAfterAt.
	if active != nil {
		return s.challenge(active.CreatedAt, active.ExpiresAt), nil
	}

	code, err := generateCode()
	if err != nil {
		return nil, fmt.Errorf("generate code: %w", err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(code), codeBcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash code: %w", err)
	}

	issued, err := s.repo.IssueAuthCode(ctx, u.ID, purpose, string(hash), time.Now().Add(s.cfg.TTL))
	if err != nil {
		return nil, fmt.Errorf("store code: %w", err)
	}

	if err := s.mailer.SendCode(ctx, u.Email, tpl, code, s.cfg.TTL); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMailDelivery, err)
	}

	return s.challenge(issued.CreatedAt, issued.ExpiresAt), nil
}

// Verify проверяет код и гасит его. Гасится он и при успехе, и только при
// успехе: неверная попытка лишь увеличивает счётчик, иначе любой желающий
// мог бы сжечь чужой код одним неправильным вводом.
func (s *Service) Verify(ctx context.Context, userID user.UserID, purpose auth.CodePurpose, code string) error {
	return s.VerifyThen(ctx, userID, purpose, code, nil)
}

// VerifyThen — Verify с проверкой между сверкой кода и его погашением.
// Нужна там, где запрос может быть отклонён уже после верного кода по
// причине, которую пользователь исправит сам (новый пароль совпал со
// старым): без неё код сгорал бы, и за исправлением пришлось бы идти
// с новым письмом. Если check вернул ошибку, код остаётся живым.
func (s *Service) VerifyThen(ctx context.Context, userID user.UserID, purpose auth.CodePurpose, code string, check func() error) error {
	stored, err := s.repo.LatestAuthCode(ctx, userID, purpose)
	if errors.Is(err, user.ErrNotFound) {
		return auth.ErrCodeInvalid
	}
	if err != nil {
		return err
	}

	if stored.Consumed() {
		return auth.ErrCodeInvalid
	}
	if stored.Expired(time.Now()) {
		return auth.ErrCodeExpired
	}
	// Счётчик проверяется до инкремента: иначе попытки продолжали бы
	// накручиваться после исчерпания лимита и однажды переполнили бы smallint.
	if stored.Attempts >= s.cfg.MaxAttempts {
		return auth.ErrCodeAttempts
	}

	attempts, err := s.repo.IncrementAuthCodeAttempts(ctx, stored.ID)
	if err != nil {
		return err
	}
	if attempts > s.cfg.MaxAttempts {
		return auth.ErrCodeAttempts
	}

	if err := bcrypt.CompareHashAndPassword([]byte(stored.CodeHash), []byte(code)); err != nil {
		return auth.ErrCodeInvalid
	}

	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}

	// Гасим в БД условием consumed_at IS NULL: две параллельные проверки
	// одного кода дадут сессию ровно одной.
	if err := s.repo.ConsumeAuthCode(ctx, stored.ID); err != nil {
		if errors.Is(err, user.ErrNotFound) {
			return auth.ErrCodeInvalid
		}
		return err
	}
	return nil
}

// Challenge собирает ответ для клиента, не выпуская код. Нужен там, где
// нельзя раскрывать существование аккаунта: клиент получает те же сроки,
// что и при реальной отправке.
func (s *Service) Challenge(now time.Time) *auth.CodeChallenge {
	return s.challenge(now, now.Add(s.cfg.TTL))
}

func (s *Service) challenge(issuedAt, expiresAt time.Time) *auth.CodeChallenge {
	return &auth.CodeChallenge{
		ExpiresAt:     expiresAt,
		ResendAfterAt: issuedAt.Add(s.cfg.ResendCooldown),
	}
}

// activeWithinCooldown возвращает последний код, если он выдан недавно и ещё
// пригоден к вводу. Погашенный не годится: после успешного ввода следующий
// запрос обязан выдать новый код, а не сослаться на использованный.
//
// Ограничение живёт здесь, а не в httprate: тот умеет ключевать только по IP
// и заголовкам, а письма на один ящик заказывают с разных адресов.
func (s *Service) activeWithinCooldown(ctx context.Context, userID user.UserID, purpose auth.CodePurpose) (*auth.AuthCode, error) {
	last, err := s.repo.LatestAuthCode(ctx, userID, purpose)
	if errors.Is(err, user.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	if last.Consumed() || last.Expired(time.Now()) {
		return nil, nil
	}
	if time.Since(last.CreatedAt) >= s.cfg.ResendCooldown {
		return nil, nil
	}
	return last, nil
}

func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, codeSpace)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", codeDigits, n), nil
}
