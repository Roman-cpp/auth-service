package config

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Service  ServiceConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Mail     MailConfig
	Codes    CodesConfig
	Account  AccountConfig
	QRLogin  QRLoginConfig
}

type ServiceConfig struct {
	Name string
	Env  string
	Port string
}

type DatabaseConfig struct {
	DSN string
}

type JWTConfig struct {
	Secret          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	// MFATokenTTL — срок промежуточного токена между вводом пароля и вводом
	// кода второго фактора. Держать близко к TTL самого кода.
	MFATokenTTL  time.Duration
	CookieDomain string
	CookieSecure bool
	// Префикс, под которым сервис виден клиенту. Gateway (nginx) публикует
	// его как /api/auth/v1/** и переписывает в /api/v1/** — куки же живут
	// в браузере, поэтому их Path должен считаться от внешнего адреса.
	// Для запуска без gateway задайте COOKIE_PATH_PREFIX=/api.
	CookiePathPrefix string
}

// MailTransport — куда уходят письма с кодами. SMTP у auth-service нет:
// письма собирает и отправляет mail-service, здесь только клиент к нему.
type MailTransport string

const (
	// MailTransportHTTP — письмо ставится в очередь mail-service подписанным
	// HTTP-запросом. Транспорт по умолчанию.
	MailTransportHTTP MailTransport = "http"
	// MailTransportLog — код пишется в лог. Режим `go run` без почтовика,
	// разрешён только для SERVICE_ENV=local.
	MailTransportLog MailTransport = "log"
)

type MailConfig struct {
	Transport  MailTransport
	ServiceURL string
	// ClientID — имя клиента в MAIL_API_KEYS почтовика, Secret — его секрет.
	ClientID string
	Secret   string
	// Timeout — на один запрос к почтовику. Запрос синхронный внутри
	// HTTP-запроса пользователя, поэтому висящий почтовик не должен
	// утаскивать за собой весь запрос в WriteTimeout сервера.
	Timeout time.Duration
	// CAFile — PEM с корнем CA почтовика, если у него не публичный
	// сертификат (режим internal в mail-service/deploy). Задан — доверие
	// только этому CA: системные корни для почтовика не используются.
	CAFile string
	// AllowInsecure разрешает http:// вне SERVICE_ENV=local. Только для
	// частной сети между серверами: коды уходят без шифрования.
	AllowInsecure bool
}

type CodesConfig struct {
	TTL            time.Duration
	ResendCooldown time.Duration
	MaxAttempts    int
}

type AccountConfig struct {
	// RestoreWindow — сколько удалённый аккаунт можно восстановить. По его
	// истечении строка удаляется физически, и адрес освобождается совсем.
	// Значение читается и при восстановлении, и уборщиком, поэтому менять
	// его на живом сервисе безопасно только в сторону увеличения:
	// сокращение немедленно делает часть аккаунтов невосстановимыми.
	RestoreWindow time.Duration
	// ModeratorEmails получают роль модератора при старте сервиса. Так
	// заводится первый модератор — назначить его иначе некому. Удаление
	// адреса из списка роль НЕ снимает.
	ModeratorEmails []string
}

type QRLoginConfig struct {
	// TTL — сколько живёт QR-код на экране. Коротко намеренно: чем дольше
	// код валиден, тем больше времени у того, кто подсунул его жертве.
	TTL time.Duration
}

func Load() (*Config, error) {
	// .env не обязателен (можно задавать переменные окружения напрямую)
	_ = godotenv.Load()

	cfg := &Config{
		Service: ServiceConfig{
			Name: getEnv("SERVICE_NAME", "auth-service"),
			Env:  getEnv("SERVICE_ENV", "local"),
			Port: getEnv("SERVICE_PORT", "8080"),
		},
		Database: DatabaseConfig{
			DSN: buildDSN(),
		},
		JWT: JWTConfig{
			Secret:           mustGetEnv("JWT_SECRET"),
			AccessTokenTTL:   parseDuration("JWT_ACCESS_TTL", 15*time.Minute),
			RefreshTokenTTL:  parseDuration("JWT_REFRESH_TTL", 7*24*time.Hour),
			MFATokenTTL:      parseDuration("JWT_MFA_TTL", 10*time.Minute),
			CookieDomain:     getEnv("COOKIE_DOMAIN", ""),
			CookieSecure:     getEnv("COOKIE_SECURE", "true") == "true",
			CookiePathPrefix: getEnv("COOKIE_PATH_PREFIX", "/api/auth"),
		},
		Mail: MailConfig{
			Transport:     MailTransport(getEnv("MAIL_TRANSPORT", string(MailTransportHTTP))),
			ServiceURL:    getEnv("MAIL_SERVICE_URL", ""),
			ClientID:      getEnv("MAIL_CLIENT_ID", "auth"),
			Secret:        getEnv("MAIL_SECRET", ""),
			Timeout:       parseDuration("MAIL_TIMEOUT", 5*time.Second),
			CAFile:        getEnv("MAIL_CA_FILE", ""),
			AllowInsecure: getEnv("MAIL_ALLOW_INSECURE", "false") == "true",
		},
		Codes: CodesConfig{
			TTL:            parseDuration("AUTH_CODE_TTL", 10*time.Minute),
			ResendCooldown: parseDuration("AUTH_CODE_RESEND_COOLDOWN", time.Minute),
			MaxAttempts:    parseInt("AUTH_CODE_MAX_ATTEMPTS", 5),
		},
		Account: AccountConfig{
			RestoreWindow:   parseDuration("ACCOUNT_RESTORE_WINDOW", 365*24*time.Hour),
			ModeratorEmails: parseList("MODERATOR_EMAILS"),
		},
		QRLogin: QRLoginConfig{
			TTL: parseDuration("AUTH_QR_TTL", 2*time.Minute),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	if len(c.JWT.Secret) < 32 {
		return fmt.Errorf("JWT_SECRET must be at least 32 characters, got %d", len(c.JWT.Secret))
	}
	switch c.Mail.Transport {
	case MailTransportLog:
		// Коды в логе вместо почты — только на машине разработчика.
		if c.Service.Env != "local" {
			return fmt.Errorf("MAIL_TRANSPORT=log is allowed only for SERVICE_ENV=local, got SERVICE_ENV=%s", c.Service.Env)
		}
	case MailTransportHTTP:
		u, err := url.Parse(c.Mail.ServiceURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("MAIL_SERVICE_URL must be an http(s) URL, got %q", c.Mail.ServiceURL)
		}
		// В запросе одноразовый код: по открытому http он допустим внутри
		// docker-сети локального стенда или по явному согласию — для частной
		// сети между серверами.
		if u.Scheme == "http" && c.Service.Env != "local" && !c.Mail.AllowInsecure {
			return fmt.Errorf("MAIL_SERVICE_URL must use https when SERVICE_ENV=%s (or set MAIL_ALLOW_INSECURE=true for a private network)", c.Service.Env)
		}
		if c.Mail.CAFile != "" && u.Scheme != "https" {
			return fmt.Errorf("MAIL_CA_FILE is set but MAIL_SERVICE_URL is not https")
		}
		if c.Mail.ClientID == "" {
			return fmt.Errorf("MAIL_CLIENT_ID must not be empty")
		}
		if len(c.Mail.Secret) < 32 {
			return fmt.Errorf("MAIL_SECRET must be at least 32 characters, got %d", len(c.Mail.Secret))
		}
		if c.Mail.Timeout <= 0 {
			return fmt.Errorf("MAIL_TIMEOUT must be positive, got %s", c.Mail.Timeout)
		}
	default:
		return fmt.Errorf("MAIL_TRANSPORT must be one of http|log, got %q", c.Mail.Transport)
	}
	if c.Codes.MaxAttempts < 1 {
		return fmt.Errorf("AUTH_CODE_MAX_ATTEMPTS must be positive, got %d", c.Codes.MaxAttempts)
	}
	// Кулдаун длиннее TTL означает, что после протухания кода новый нельзя
	// запросить — пользователь запирается на ровном месте.
	if c.Codes.ResendCooldown > c.Codes.TTL {
		return fmt.Errorf("AUTH_CODE_RESEND_COOLDOWN (%s) must not exceed AUTH_CODE_TTL (%s)",
			c.Codes.ResendCooldown, c.Codes.TTL)
	}
	// MFA-токен короче кода сделал бы код недоступным: клиент потерял бы
	// право его предъявить раньше, чем код перестал быть валидным.
	if c.JWT.MFATokenTTL < c.Codes.TTL {
		return fmt.Errorf("JWT_MFA_TTL (%s) must be at least AUTH_CODE_TTL (%s)",
			c.JWT.MFATokenTTL, c.Codes.TTL)
	}
	// Ноль означал бы «удалять физически сразу», а это делает уборщик по
	// таймеру: до его прохода аккаунт висел бы удалённым и невосстановимым.
	// Такой режим нужно вводить осознанно, а не опечаткой в переменной.
	if c.Account.RestoreWindow <= 0 {
		return fmt.Errorf("ACCOUNT_RESTORE_WINDOW must be positive, got %s", c.Account.RestoreWindow)
	}
	// Верхняя граница — та же, что у одноразового кода: QR, который живёт
	// дольше, опаснее кода из письма, а удобнее не становится.
	if c.QRLogin.TTL <= 0 || c.QRLogin.TTL > c.Codes.TTL {
		return fmt.Errorf("AUTH_QR_TTL must be positive and not exceed AUTH_CODE_TTL (%s), got %s",
			c.Codes.TTL, c.QRLogin.TTL)
	}
	return nil
}

func buildDSN() string {
	dsn := os.Getenv("DATABASE_URL")
	if dsn != "" {
		return dsn
	}
	host := getEnv("DB_HOST", "postgres")
	port := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "postgres")
	pass := getEnv("DB_PASSWORD", "postgres")
	name := getEnv("DB_NAME", "auth-db")

	// url.UserPassword экранирует спецсимволы (/, @, + и т.д.) в userinfo —
	// без этого сгенерированный `openssl rand -base64` пароль может сломать парсинг DSN
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(dbUser, pass),
		Host:     fmt.Sprintf("%s:%s", host, port),
		Path:     "/" + name,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func mustGetEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic(fmt.Sprintf("required env variable %q is not set", key))
	}
	return v
}

func parseInt(key string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return v
}

// parseList разбирает список через запятую, пропуская пустые элементы.
func parseList(key string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	// Пробуем парсить как секунды
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	// Пробуем парсить как Go duration string (e.g. "15m", "24h")
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}
