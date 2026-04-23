package router

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/krypton/auth-service/internal/handler"
)

func Setup(r *gin.Engine, h *handler.AuthHandler, authMw gin.HandlerFunc) {
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1/auth")
	{
		v1.POST("/register", h.Register)
		v1.POST("/login", h.Login)
		v1.POST("/refresh", h.Refresh)

		protected := v1.Group("", authMw)
		{
			protected.POST("/logout", h.Logout)
			protected.GET("/me", h.Me)
		}
	}
}
