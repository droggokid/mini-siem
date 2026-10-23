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
		identity, err := t.Validate(bearer(c.Request))
		authenticate(c, identity, err)
	}
}

func (t *Tokens) EventMiddleware(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ownerID, err := t.ValidateEvent(bearer(c.Request), action)
		authenticate(c, Identity{ID: ownerID}, err)
	}
}

func bearer(r *http.Request) string {
	header := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) == 1 && len(header) == 2 && strings.EqualFold(header[0], "Bearer") {
		return header[1]
	}
	return ""
}

func authenticate(c *gin.Context, identity Identity, err error) {
	c.Header("Cache-Control", "no-store")
	if err != nil {
		c.Header("WWW-Authenticate", "Bearer")
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), identityKey{}, identity))
	c.Next()
}
