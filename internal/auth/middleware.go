package auth

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type identityKey struct{}

func FromContext(ctx context.Context) (Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(Identity)
	return identity, ok
}

// Middleware authenticates the user; routes must still enforce roles and ownership.
func (t *Tokens) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		identity, err := t.Validate(bearer(c.Request))
		authenticate(c, identity, err)
	}
}

// EventMiddleware authorizes one exact Event action and sets its verified principal.
func (t *Tokens) EventMiddleware(action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ownerID, err := t.ValidateEvent(bearer(c.Request), action)
		authenticate(c, Identity{ID: ownerID}, err)
	}
}

type jobKey struct{}

func JobFromContext(ctx context.Context) JobScope {
	scope, _ := ctx.Value(jobKey{}).(JobScope)
	return scope
}

// JobMiddleware requires delegated owner/job scope, not blanket trust in another service.
func JobMiddleware(key ed25519.PublicKey, service, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		scope, err := VerifyJob(key, bearer(c.Request), service, action)
		// Bind signed authority to this request's job; a header alone grants no permission.
		if len(c.Request.Header.Values(JobHeader)) != 1 || c.GetHeader(JobHeader) != scope.JobID {
			err = errors.New("mismatched job")
		}

		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), jobKey{}, scope))
		authenticate(c, Identity{ID: scope.OwnerID}, err)
	}
}

func bearer(r *http.Request) string {
	header := strings.Fields(r.Header.Get("Authorization"))
	// Reject ambiguous headers instead of choosing between multiple credentials.
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
