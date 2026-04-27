package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/joho/godotenv"
)

//go:embed migrations/*
var FS embed.FS

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	_ = godotenv.Load()

	defaultDSN := fmt.Sprintf("pgx5://%s:%s@%s:%s/%s?sslmode=disable",
		getenv("DB_USER", "postgres"),
		getenv("DB_PASSWORD", "postgres"),
		getenv("DB_HOST", "localhost"),
		getenv("DB_PORT", "5432"),
		getenv("DB_NAME", "auth-db"),
	)
	dsn := flag.String("dsn", defaultDSN, "database DSN")
	flag.Parse()

	cmd := flag.Arg(0)
	if cmd == "" {
		log.Fatal("usage: migrate -dsn <dsn> [up|down|version]")
	}

	src, err := iofs.New(FS, "migrations")
	if err != nil {
		log.Fatalf("migrations source: %v", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, *dsn)
	if err != nil {
		log.Fatalf("migrate init: %v", err)
	}
	defer m.Close()

	switch cmd {
	case "up":
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("up: %v", err)
		}
		fmt.Println("migrations applied")

	case "down":
		if err := m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			log.Fatalf("down: %v", err)
		}
		fmt.Println("rolled back one migration")

	case "version":
		v, dirty, err := m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			log.Fatalf("version: %v", err)
		}
		fmt.Printf("version=%d dirty=%v\n", v, dirty)

	default:
		log.Fatalf("unknown command: %s (use up|down|version)", cmd)
	}
}
