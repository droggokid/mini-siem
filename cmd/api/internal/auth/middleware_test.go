package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
	"github.com/gin-gonic/gin"
)

func assertRejected(t *testing.T, tokens *Tokens, raw string) {
	t.Helper()
	if identity, err := tokens.Validate(raw); err == nil || identity != (Identity{}) {
		t.Fatal("invalid token produced an authenticated identity")
	}
	r := httptest.NewRequest("GET", "/me", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	router := gin.New()
	router.GET("/me", tokens.Middleware(), func(*gin.Context) {
		t.Fatal("invalid token reached protected handler")
	})
	router.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("status=%d, want 401 with bearer challenge", w.Code)
	}
}

func TestMiddlewareSetsIdentity(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("unauthenticated context has an identity")
	}
	tokens, _ := testTokens(t)
	raw, err := tokens.Sign(users.User{ID: 2, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	handler := gin.New()
	handler.GET("/me", tokens.Middleware(), func(c *gin.Context) {
		identity, ok := FromContext(c.Request.Context())
		if !ok || identity != (Identity{ID: 2, Role: "user"}) {
			t.Fatal("verified identity missing from request context")
		}
		c.Status(http.StatusNoContent)
	})
	for _, duplicate := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/me", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		if duplicate {
			r.Header.Add("Authorization", "Bearer "+raw)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		want := http.StatusNoContent
		if duplicate {
			want = http.StatusUnauthorized
		}
		if w.Code != want {
			t.Fatalf("duplicate=%t status=%d, want %d", duplicate, w.Code, want)
		}
	}
}
