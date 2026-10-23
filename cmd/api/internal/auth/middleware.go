package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type identityKey struct{}

func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}

func (t *Tokens) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		header := strings.Fields(c.GetHeader("Authorization"))
		raw := ""

		if len(c.Request.Header.Values("Authorization")) == 1 && len(header) == 2 && strings.EqualFold(header[0], "Bearer") {
			raw = header[1]
		}

		identity, err := t.Validate(raw)
		if err != nil {
			c.Header("WWW-Authenticate", "Bearer")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), identityKey{}, identity))
		c.Next()
	}
}
