package main

import (
	"crypto/ed25519"
	"crypto/rand"
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

func TestDetectionAPIDelegatesOnlyAuthenticatedOwner(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		scope, err := auth.VerifyJob(public, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), auth.DetectionService, auth.RunDetection)
		if err != nil || scope.JobID != r.Header.Get(auth.JobHeader) || r.URL.Path != "/detections/run" {
			t.Error("invalid run authority")
		}
		var input struct {
			ReadToken  string `json:"read_token"`
			WriteToken string `json:"write_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			t.Error(err)
		}
		read, readErr := auth.VerifyJob(public, input.ReadToken, auth.EventService, auth.ListEvents)
		write, writeErr := auth.VerifyJob(public, input.WriteToken, auth.EventService, auth.AddAlerts)
		if readErr != nil || writeErr != nil || read != scope || write != scope {
			t.Error("mismatched delegated permissions")
		}
		fmt.Fprintf(w, `{"owner_id":%d}`, scope.OwnerID)
	}))
	defer server.Close()
	store, err := users.Open(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	userTokens, _ := auth.New([]byte(strings.Repeat("u", 32)))
	eventTokens, _ := auth.New([]byte(strings.Repeat("e", 32)))
	handler := newRouter(store, userTokens, server.URL, eventTokens, server.URL, private)

	for i, user := range []string{"Alice", "Bob", "Admin"} {
		token := login(t, handler, user, strings.ToLower(user)+"-password")
		w := request(handler, "POST", "/detections/run", "", token)
		if w.Code != 200 || w.Body.String() != fmt.Sprintf(`{"owner_id":%d}`, i+1) {
			t.Fatalf("%s: %d %s", user, w.Code, w.Body)
		}
	}

	token := login(t, handler, "Bob", "bob-password")
	for _, tt := range []struct {
		path, body, token string
		status            int
	}{
		{"/detections/run", "", "", 401},
		{"/detections/run", `{"owner_id":1}`, token, 400},
		{"/detections/run?owner_id=1", "", token, 400},
		{"/detections/run", "null", token, 400},
		{"/detections/run", "[]", token, 400},
		{"/detections/run", "{} {}", token, 400},
		{"/detections/run", strings.Repeat(" ", 65537), token, 413},
	} {
		w := request(handler, "POST", tt.path, tt.body, tt.token)
		if w.Code != tt.status {
			t.Fatalf("got %d %s want %d", w.Code, w.Body, tt.status)
		}
	}
	if calls.Load() != 3 {
		t.Fatal("invalid requests reached Detection")
	}
	if w := request(handler, "POST", "/detections/run", "{ }", token); w.Code != 200 {
		t.Fatalf("empty JSON object: %d %s", w.Code, w.Body)
	}
}

func TestAlertAPIDelegation(t *testing.T) {
	tokens, _ := auth.New([]byte(strings.Repeat("s", 32)))
	handler := eventAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		owner, err := tokens.ValidateEvent(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), auth.ListAlerts)
		if err != nil || r.URL.Path != "/alerts" {
			t.Error("invalid alert authority")
		}
		fmt.Fprintf(w, `[{"owner_id":%d}]`, owner)
	}))
	for i, user := range []string{"Alice", "Bob", "Admin"} {
		token := login(t, handler, user, strings.ToLower(user)+"-password")
		w := request(handler, "GET", "/alerts", "", token)
		if w.Code != 200 || w.Body.String() != fmt.Sprintf(`[{"owner_id":%d}]`, i+1) {
			t.Fatalf("%s: %d %s", user, w.Code, w.Body)
		}
		for _, path := range []string{"/alerts?owner_id=1", "/alerts?all=true"} {
			if w := request(handler, "GET", path, "", token); w.Code != 400 {
				t.Fatal("accepted alert owner query")
			}
		}
	}
}
