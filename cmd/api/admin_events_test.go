package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestAdminEventsDelegation(t *testing.T) {
	eventTokens, err := auth.New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	handler := eventAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		principal, err := eventTokens.ValidateEvent(raw, "events:list_all")
		if err != nil || principal != 3 || r.Method != "GET" || r.URL.Path != "/admin/events" || r.URL.RawQuery != "" {
			t.Errorf("invalid privileged delegation: principal=%d err=%v method=%s URL=%s", principal, err, r.Method, r.URL)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `[{"owner_id":1},{"owner_id":2},{"owner_id":3}]`)
	}))
	token := login(t, handler, "Admin", "admin-password")
	w := request(handler, "GET", "/admin/events", "", token)
	if w.Code != http.StatusOK || w.Body.String() != `[{"owner_id":1},{"owner_id":2},{"owner_id":3}]` || calls.Load() != 1 {
		t.Fatalf("admin listing: %d %s calls=%d", w.Code, w.Body, calls.Load())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("admin events may be cached")
	}
}

func TestAdminEventsRejectBeforeDelegation(t *testing.T) {
	var calls atomic.Int32
	handler := eventAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	expired, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "mini-siem", "aud": "mini-siem-api", "sub": "3", "role": "admin",
		"exp": time.Now().Add(-time.Minute).Unix(),
	}).SignedString([]byte(strings.Repeat("u", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "Bearer not-a-jwt", "Bearer " + expired} {
		if w := request(handler, "GET", "/admin/events", "", token); w.Code != http.StatusUnauthorized {
			t.Fatalf("unauthenticated listing: status=%d, want 401", w.Code)
		}
	}
	for _, user := range []string{"Alice", "Bob"} {
		token := login(t, handler, user, strings.ToLower(user)+"-password")
		if w := request(handler, "GET", "/admin/events", "", token); w.Code != http.StatusForbidden {
			t.Fatalf("%s listing: status=%d, want 403", user, w.Code)
		}
	}
	token := login(t, handler, "Admin", "admin-password")
	for _, tt := range []struct {
		path, body string
		status     int
	}{
		{"/admin/events?owner_id=1", "", 400},
		{"/admin/events?limit=1", "", 400},
		{"/admin/events?%zz", "", 400},
		{"/admin/events", `{"owner_id":1}`, 400},
		{"/admin/events", "{}", 400},
		{"/admin/events", strings.Repeat("x", 64*1024+1), 413},
	} {
		if w := request(handler, "GET", tt.path, tt.body, token); w.Code != tt.status {
			t.Fatalf("invalid admin request %s: status=%d, want %d", tt.path, w.Code, tt.status)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("rejected requests received delegated authority and reached Event")
	}
}

func TestAdminEventsChecksRoleBeforeSigning(t *testing.T) {
	tokens, err := auth.New([]byte(strings.Repeat("u", 32)))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := tokens.Sign(auth.Identity{ID: 3, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	// A nil delegation signer would panic if reached before the role check.
	handler := newRouter(nil, tokens, "http://event:8080", nil, "http://detection:8080", nil)
	if w := request(handler, "GET", "/admin/events", "", "Bearer "+raw); w.Code != http.StatusForbidden {
		t.Fatalf("role check before signing: status=%d", w.Code)
	}
}
