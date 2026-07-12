package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Service  ServiceConfig
	Database DatabaseConfig
	JWT      JWTConfig
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
	CookieDomain    string
	CookieSecure    bool
	// Префикс, под которым сервис виден клиенту. Gateway (nginx) публикует
	// его как /api/auth/v1/** и переписывает в /api/v1/** — куки же живут
	// в браузере, поэтому их Path должен считаться от внешнего адреса.
	// Для запуска без gateway задайте COOKIE_PATH_PREFIX=/api.
	CookiePathPrefix string
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
			Secret:          mustGetEnv("JWT_SECRET"),
			AccessTokenTTL:  parseDuration("JWT_ACCESS_TTL", 15*time.Minute),
			RefreshTokenTTL: parseDuration("JWT_REFRESH_TTL", 7*24*time.Hour),
			CookieDomain:    getEnv("COOKIE_DOMAIN", ""),
			CookieSecure:     getEnv("COOKIE_SECURE", "true") == "true",
			CookiePathPrefix: getEnv("COOKIE_PATH_PREFIX", "/api/auth"),
		},
	}

	return cfg, nil
}

func buildDSN() string {
	dsn := os.Getenv("DATABASE_URL")
	if dsn != "" {
		return dsn
	}
	host := getEnv("DB_HOST", "postgres")
	port := getEnv("DB_PORT", "5432")
	user := getEnv("DB_USER", "postgres")
	pass := getEnv("DB_PASSWORD", "postgres")
	name := getEnv("DB_NAME", "auth-db")
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port, name)
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
