# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-service ./cmd/auth-service/main.go
RUN CGO_ENABLED=0 GOOS=linux go build -o /auth-migrate ./cmd/migrate/main.go

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /auth-service .
COPY --from=builder /auth-migrate .

EXPOSE 8100

ENTRYPOINT ["/app/auth-service"]
