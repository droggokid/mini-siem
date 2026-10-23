package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
	raw, err := tokens.Sign(Identity{ID: 2, Role: "user"})
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

func TestEventMiddlewareSetsScopedOwner(t *testing.T) {
	tokens, _ := testTokens(t)
	valid, err := tokens.SignEvent(2, ListEvents)
	if err != nil {
		t.Fatal(err)
	}
	wrongAction, err := tokens.SignEvent(2, AddEvent)
	if err != nil {
		t.Fatal(err)
	}
	userJWT, err := tokens.Sign(Identity{ID: 2, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	handler := gin.New()
	handler.GET("/events", tokens.EventMiddleware(ListEvents), func(c *gin.Context) {
		identity, ok := FromContext(c.Request.Context())
		if !ok || identity != (Identity{ID: 2}) {
			t.Fatalf("wrong scoped owner: %+v, %t", identity, ok)
		}
		c.Status(http.StatusNoContent)
	})
	for _, tt := range []struct {
		name, header string
		duplicate    bool
		want         int
	}{
		{"valid", "Bearer " + valid, false, http.StatusNoContent},
		{"lowercase bearer", "bearer " + valid, false, http.StatusNoContent},
		{"wrong action", "Bearer " + wrongAction, false, http.StatusUnauthorized},
		{"user JWT", "Bearer " + userJWT, false, http.StatusUnauthorized},
		{"missing", "", false, http.StatusUnauthorized},
		{"malformed", "Bearer a.b.c", false, http.StatusUnauthorized},
		{"extra field", "Bearer " + valid + " other", false, http.StatusUnauthorized},
		{"duplicate", "Bearer " + valid, true, http.StatusUnauthorized},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/events", nil)
			r.Header.Set("Authorization", tt.header)
			if tt.duplicate {
				r.Header.Add("Authorization", tt.header)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tt.want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d, want %d with no-store", w.Code, tt.want)
			}
			if tt.want == http.StatusUnauthorized && w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("missing bearer challenge")
			}
		})
	}
}
