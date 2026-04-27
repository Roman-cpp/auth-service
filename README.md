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

Обязательно задайте `JWT_SECRET` — сервис не запустится без него:

```bash
# Генерация надёжного секрета
openssl rand -hex 32
```

Основные переменные `.env`:

| Переменная       | По умолчанию                                    | Описание               |
|------------------|-------------------------------------------------|------------------------|
| `SERVICE_NAME`   | `auth-service`                                  | Имя сервиса            |
| `SERVICE_ENV`    | `local`                                         | Окружение              |
| `SERVICE_PORT`   | `8080`                                          | Порт внутри контейнера |
| `DB_HOST`        | `postgres`                                      | Хост БД                |
| `DB_PORT`        | `5432`                                          | Порт БД                |
| `DB_USER`        | `postgres`                                      | Пользователь БД        |
| `DB_PASSWORD`    | `postgres`                                      | Пароль БД              |
| `DB_NAME`        | `auth-db`                                       | Имя базы данных        |
| `JWT_SECRET`     | —                                               | **Обязателен**         |
| `JWT_ACCESS_TTL` | `15m`                                           | TTL access-токена      |
| `JWT_REFRESH_TTL`| `168h`                                          | TTL refresh-токена     |

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
