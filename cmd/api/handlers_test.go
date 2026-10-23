package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/droggokid/mini-siem/cmd/api/internal/users"
	"github.com/droggokid/mini-siem/internal/auth"
)

func testAPI(t *testing.T) (http.Handler, *users.Store) {
	t.Helper()
	store, err := users.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.New(secret)
	if err != nil {
		t.Fatal(err)
	}
	eventTokens, err := auth.New([]byte(strings.Repeat("e", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return newRouter(store, tokens, "http://event:8080", eventTokens), store
}

func request(handler http.Handler, method, path, body, authorization string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func TestLoginAndMe(t *testing.T) {
	handler, _ := testAPI(t)
	for _, tt := range []struct {
		username, password, role string
		id                       int64
	}{
		{"Alice", "alice-password", "user", 1}, {"Bob", "bob-password", "user", 2}, {"Admin", "admin-password", "admin", 3},
	} {
		t.Run(tt.username, func(t *testing.T) {
			w := request(handler, "POST", "/login", fmt.Sprintf(`{"username":%q,"password":%q}`, tt.username, tt.password), "")
			if w.Code != http.StatusOK {
				t.Fatalf("login status=%d", w.Code)
			}
			var response struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
				ExpiresIn   int    `json:"expires_in"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.AccessToken == "" || response.TokenType != "Bearer" || response.ExpiresIn != 900 {
				t.Fatal("missing token response fields")
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("login response can be cached")
			}
			if strings.Contains(w.Body.String(), tt.password) || strings.Contains(w.Body.String(), "password_hash") {
				t.Fatal("login response exposes credentials")
			}
			for _, scheme := range []string{"Bearer", "bearer"} {
				me := request(handler, "GET", "/me", "", scheme+" "+response.AccessToken)
				if me.Code != http.StatusOK {
					t.Fatalf("me status=%d", me.Code)
				}
				var identity auth.Identity
				if err := json.Unmarshal(me.Body.Bytes(), &identity); err != nil {
					t.Fatal(err)
				}
				if identity.ID != tt.id || identity.Role != tt.role {
					t.Fatalf("unexpected identity: %+v", identity)
				}
			}
		})
	}
	if w := request(handler, "GET", "/health", "", ""); w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Fatal("health endpoint changed")
	}
}

func TestLoginRejectsCredentials(t *testing.T) {
	handler, _ := testAPI(t)
	var failure string
	for _, body := range []string{`{"username":"Alice","password":"wrong"}`, `{"username":"unknown","password":"wrong"}`, `{"username":"' OR 1=1 --","password":"wrong"}`} {
		w := request(handler, "POST", "/login", body, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want 401", w.Code)
		}
		var response struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Error == "" {
			t.Fatal("login errors must return a JSON error message")
		}
		if failure != "" && failure != w.Body.String() {
			t.Fatal("login errors distinguish unknown users from wrong passwords")
		}
		failure = w.Body.String()
	}
}

func TestLoginRejectsInvalidInput(t *testing.T) {
	handler, _ := testAPI(t)
	for _, body := range []string{"", "{", "null", "[]", `{}`, `{"username":"Alice"}`, `{"username":4,"password":"wrong"}`, `{"username":"Alice","password":"wrong","role":"admin"}`, `{"username":"Alice","password":"wrong"} {}`, `{"username":"Alice","password":"wrong"} garbage`} {
		if w := request(handler, "POST", "/login", body, ""); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid input status=%d, want 400", w.Code)
		}
	}
	valid := `{"username":"Alice","password":"alice-password"}`
	for _, size := range []int{64 * 1024, 64*1024 + 1} {
		w := request(handler, "POST", "/login", valid+strings.Repeat(" ", size-len(valid)), "")
		want := http.StatusOK
		if size > 64*1024 {
			want = http.StatusRequestEntityTooLarge
		}
		if w.Code != want {
			t.Fatalf("body size=%d status=%d, want %d", size, w.Code, want)
		}
	}
	r := httptest.NewRequest("POST", "/login", strings.NewReader(valid))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type status=%d, want 415", w.Code)
	}
}

func TestMeRejectsInvalidAuthentication(t *testing.T) {
	handler, _ := testAPI(t)
	for _, header := range []string{"", "Bearer", "Basic abc", "Bearer not-a-jwt", "Bearer a b", "Bearer a.b.c"} {
		w := request(handler, "GET", "/me", "", header)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatalf("invalid authentication status=%d", w.Code)
		}
	}
}

func TestLoginHidesStorageErrors(t *testing.T) {
	handler, store := testAPI(t)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	w := request(handler, "POST", "/login", `{"username":"Alice","password":"alice-password"}`, "")
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "database") || strings.Contains(w.Body.String(), "alice-password") {
		t.Fatal("storage failure must return a generic server error")
	}
}
