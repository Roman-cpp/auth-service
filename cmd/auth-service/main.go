package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/handler"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/repository"
	"github.com/krypton/auth-service/internal/router"
	"github.com/krypton/auth-service/internal/service"
)

func main() {
	cfg, _ := config.Load()
	

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer pool.Close()
	

	userRepo := repository.NewUserRepository(pool)
	authSvc := service.NewAuthService(userRepo, cfg)
	userSvc := service.NewUserService(userRepo)
	authHandler := handler.NewAuthHandler(authSvc)
	userHandler := handler.NewUserHandler(userSvc)

	r := chi.NewRouter()
	authMiddleware := middleware.JWTAuth(authSvc)
	router.NewRouter(r, authHandler, userHandler, authMiddleware)

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("server listening on :%s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("server shutdown: %v", err)
	}
	log.Println("server stopped")
}
