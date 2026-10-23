package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
	"github.com/droggokid/mini-siem/internal/auth"
)

func eventAPI(t *testing.T, upstream http.Handler) http.Handler {
	t.Helper()
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	store, err := users.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	userTokens, err := auth.New([]byte(strings.Repeat("u", 32)))
	if err != nil {
		t.Fatal(err)
	}
	eventTokens, err := auth.New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return newRouter(store, userTokens, server.URL, eventTokens)
}

func login(t *testing.T, handler http.Handler, username, password string) string {
	t.Helper()
	w := request(handler, "POST", "/login", fmt.Sprintf(`{"username":%q,"password":%q}`, username, password), "")
	var response struct {
		Token string `json:"access_token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Token == "" {
		t.Fatalf("login failed: %d %s", w.Code, w.Body)
	}
	return "Bearer " + response.Token
}

func TestEventsDelegateAuthenticatedOwner(t *testing.T) {
	tokens, err := auth.New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	handler := eventAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		action := auth.ListEvents
		if r.Method == "POST" {
			action = auth.AddEvent
		}
		owner, err := tokens.ValidateEvent(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), action)
		if err != nil || r.URL.Path != "/events" || r.URL.RawQuery != "" {
			t.Errorf("invalid delegated request: owner=%d err=%v URL=%s", owner, err, r.URL)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method == "POST" {
			var input map[string]string
			if json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 2 || input["type"] != "login.failed" || input["source_ip"] != "192.0.2.1" {
				t.Error("API changed the event body")
			}
			w.WriteHeader(http.StatusCreated)
		}
		fmt.Fprintf(w, `{"owner_id":%d}`, owner)
	}))
	for _, tt := range []struct {
		name, password string
		owner          int64
	}{{"Alice", "alice-password", 1}, {"Bob", "bob-password", 2}, {"Admin", "admin-password", 3}} {
		token := login(t, handler, tt.name, tt.password)
		for _, method := range []string{"POST", "GET"} {
			body, status := "", http.StatusOK
			if method == "POST" {
				body, status = `{"type":"login.failed","source_ip":"192.0.2.1"}`, http.StatusCreated
			}
			w := request(handler, method, "/events", body, token)
			if w.Code != status || w.Body.String() != fmt.Sprintf(`{"owner_id":%d}`, tt.owner) {
				t.Fatalf("%s %s: %d %s", tt.name, method, w.Code, w.Body)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("events may be cached")
			}
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("delegated %d requests, want 6", calls.Load())
	}
}

func TestEventsRejectUnauthorizedAndOversizedRequests(t *testing.T) {
	var calls atomic.Int32
	handler := eventAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	for _, method := range []string{"POST", "GET"} {
		for _, token := range []string{"", "Bearer not-a-jwt"} {
			if w := request(handler, method, "/events", "", token); w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthorized %s status=%d", method, w.Code)
			}
		}
	}
	token := login(t, handler, "Bob", "bob-password")
	for _, method := range []string{"POST", "GET"} {
		if w := request(handler, method, "/events", strings.Repeat("x", 64*1024+1), token); w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized %s status=%d", method, w.Code)
		}
		if w := request(handler, method, "/events?owner_id=1", "", token); w.Code != http.StatusBadRequest {
			t.Fatalf("owner query %s status=%d", method, w.Code)
		}
	}
	if w := request(handler, "GET", "/events", "{}", token); w.Code != http.StatusBadRequest {
		t.Fatal("accepted GET body")
	}
	if calls.Load() != 0 {
		t.Fatal("rejected requests reached Event")
	}
}

func TestEventsHandleUpstreamFailures(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError, http.StatusTemporaryRedirect} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			handler := eventAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://127.0.0.1:1/steal-token")
				w.WriteHeader(status)
				fmt.Fprint(w, "internal secret details")
			}))
			w := request(handler, "GET", "/events", "", login(t, handler, "Alice", "alice-password"))
			if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("upstream error leaked or wrong status: %d %s", w.Code, w.Body)
			}
		})
	}
}
