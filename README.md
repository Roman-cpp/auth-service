# auth-service

Сервис аутентификации на Go. Построен по принципам DDD.

## Требования

- [Docker](https://docs.docker.com/get-docker/) + Docker Compose
- [Go 1.24+](https://go.dev/dl/) (только для локального запуска без Docker)

## Быстрый старт

### 1. Настройка переменных окружения

```bash
cp .env.example .env
```

Токены подписываются **RS256**. Сгенерируйте RSA-пару — приватный ключ
остаётся в сервисе, `jwt_public.pem` раздаётся потребителям
(`trading-backend`, `keys-service`), которые проверяют токены офлайн:

```bash
# RSA-пара -> ./secrets/jwt_private.pem + ./secrets/jwt_public.pem
go run ./cmd/genkey -out ./secrets
```

Обязателен `JWT_PRIVATE_KEY_PATH` — без него сервис не запустится.

Основные переменные `.env`:

| Переменная                        | По умолчанию                  | Описание                                              |
|-----------------------------------|-------------------------------|-------------------------------------------------------|
| `SERVICE_NAME`                    | `auth-service`                | Имя сервиса                                           |
| `SERVICE_ENV`                     | `local`                       | Окружение                                             |
| `SERVICE_PORT`                    | `8080`                        | Порт внутри контейнера                                |
| `DB_HOST`                         | `postgres`                    | Хост БД                                               |
| `DB_PORT`                         | `5432`                        | Порт БД                                               |
| `DB_USER`                         | `postgres`                    | Пользователь БД                                       |
| `DB_PASSWORD`                     | `postgres`                    | Пароль БД                                             |
| `DB_NAME`                         | `auth-db`                     | Имя базы данных                                       |
| `JWT_PRIVATE_KEY_PATH`            | —                             | **Обязателен**. RSA-приватный ключ (PEM)              |
| `JWT_ADDITIONAL_PUBLIC_KEY_PATHS` | —                             | Доп. публичные ключи для ротации (через запятую)      |
| `JWT_ISSUER`                      | `sleipnir-auth`               | Claim `iss`                                           |
| `JWT_AUDIENCE`                    | `trading-backend,keys-service`| Claim `aud` (массив)                                  |
| `JWT_ACCESS_TTL`                  | `15m`                         | TTL access-токена                                     |
| `JWT_REFRESH_TTL`                 | `168h`                        | TTL refresh-токена                                    |

### Распространение публичного ключа

Потребители получают ключ одним из способов:

- `GET /.well-known/jwks.json` — JWKS с `kid` (предпочтительно);
- `GET /.well-known/jwt_public.pem` — статический PKIX PEM.

### Ротация ключей без даунтайма

1. Сгенерировать новую пару, добавить **старый** публичный ключ в
   `JWT_ADDITIONAL_PUBLIC_KEY_PATHS`, а новый приватный — в `JWT_PRIVATE_KEY_PATH`.
2. Дождаться, пока все потребители подтянут новый ключ (JWKS отдаёт оба `kid`).
3. Убрать старый ключ из `JWT_ADDITIONAL_PUBLIC_KEY_PATHS`.

### 2. Запуск

```bash
docker compose up --build
```

Сервис будет доступен на `http://localhost:8085`.

Для dev-окружения:

```bash
docker compose -f docker-compose-dev.yml up --build
```

### 3. Миграции

Миграции применяются автоматически при первом запуске через `docker-entrypoint-initdb.d`.

Для ручного управления миграциями:

```bash
# Применить все
go run ./cmd/migrate up

# Откатить последнюю
go run ./cmd/migrate down

# Текущая версия
go run ./cmd/migrate version
```

DSN подтягивается из `.env` автоматически. Можно переопределить флагом:

```bash
go run ./cmd/migrate -dsn "pgx5://user:pass@host:5432/db" up
```

## Локальный запуск без Docker

```bash
# Запустить только БД
docker compose up postgres -d

# Запустить сервис
go run ./cmd/auth-service
```

## Структура проекта

```
cmd/
  auth-service/   — точка входа сервиса
  migrate/        — CLI для управления миграциями
internal/
  config/         — загрузка конфигурации из env
  domain/         — бизнес-логика (DDD-агрегаты)
  handler/        — HTTP-обработчики
  middleware/     — JWT и прочие middleware
  repository/     — реализации репозиториев (PostgreSQL)
  router/         — маршрутизация
  service/        — реализации сервисов
migrations/       — SQL-миграции
docs/             — документация по доменной модели
```
