package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/krypton/auth-service/internal/config"
	"github.com/krypton/auth-service/internal/handler"
	"github.com/krypton/auth-service/internal/middleware"
	"github.com/krypton/auth-service/internal/repository"
	"github.com/krypton/auth-service/internal/service"
)

func main() {
	// 1. Конфигурация
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// 2. Подключение к PostgreSQL
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.Database.DSN)
	if err != nil {
		log.Fatalf("db connect: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("db ping: %v", err)
	}
	log.Println("connected to PostgreSQL")

	// 3. Сборка слоёв
	userRepo := repository.NewUserRepository(pool)
	authSvc := service.NewAuthService(userRepo, cfg)
	authHandler := handler.NewAuthHandler(authSvc)

	// 4. HTTP-сервер
	r := gin.Default()
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	authMiddleware := middleware.JWTAuth(authSvc)
	authHandler.RegisterRoutes(r, authMiddleware)

	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// 5. Graceful shutdown
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
