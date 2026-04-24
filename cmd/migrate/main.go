package main

import (
	"embed"
	"errors"
	"flag"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*
var FS embed.FS

func main() {
	dsn := flag.String("dsn", "pgx5://postgres:postgres@localhost:5432/postgres?sslmode=disable", "database DSN")
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
