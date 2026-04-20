package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/krypton/auth-service/internal/service"
)

// JWTAuth возвращает middleware, который проверяет Bearer-токен в заголовке Authorization.
// При успехе помещает user_id и email в контекст gin.
func JWTAuth(svc *service.AuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := extractBearer(c)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization header required"})
			return
		}

		claims, err := svc.ValidateAccessToken(token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired access token"})
			return
		}

		c.Set("user_id", claims.UserID.String())
		c.Set("email", claims.Email)
		c.Next()
	}
}

func extractBearer(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	parts := strings.SplitN(header, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return parts[1]
	}
	return ""
}
