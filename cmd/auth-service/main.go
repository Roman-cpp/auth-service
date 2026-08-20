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
	"github.com/krypton/auth-service/internal/keys"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/repository"
	"github.com/krypton/auth-service/internal/router"
	"github.com/krypton/auth-service/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config load: %v", err)
	}

	keySet, err := keys.Load(cfg.JWT.PrivateKeyPath, cfg.JWT.AdditionalPublicKeyPaths)
	if err != nil {
		log.Fatalf("load signing keys: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer pool.Close()


	userRepo := repository.NewUserRepository(pool)
	authSvc := service.NewAuthService(userRepo, cfg, keySet)
	userSvc := service.NewUserService(userRepo)
	authHandler := handler.NewAuthHandler(authSvc, cfg)
	userHandler := handler.NewUserHandler(userSvc)
	jwksHandler := handler.NewJWKSHandler(keySet)

	r := chi.NewRouter()
	authMiddleware := middleware.JWTAuth(authSvc)
	router.NewRouter(r, authHandler, userHandler, jwksHandler, authMiddleware)

	srv := &http.Server{
		Addr:         ":" + cfg.Service.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("server listening on :%s", cfg.Service.Port)
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
