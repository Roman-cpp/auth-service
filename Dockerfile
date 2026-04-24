# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Копируем файлы зависимостей
COPY go.mod go.sum ./
RUN go mod download

# Копируем весь исходный код
COPY . .

# Собираем бинарник
RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-service ./cmd/auth-service/main.go

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

# Устанавливаем необходимые пакеты
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Копируем бинарник из builder
COPY --from=builder /auth-service .

# Копируем папку с миграциями (ВАЖНО!)
# COPY --from=builder /app/migrations ./migrations

# Проверяем, что миграции скопировались (опционально, для отладки)
# RUN ls -la /app/migrations/

EXPOSE 8100

# Используем переменную окружения для пути к миграциям
# ENV MIGRATIONS_PATH=/app/migrations

ENTRYPOINT ["/app/auth-service"]
