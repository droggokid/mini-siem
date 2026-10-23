package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/droggokid/mini-siem/cmd/event/internal/events"
	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func TestAdminEventsListAll(t *testing.T) {
	handler, tokens := testHandler(t)
	list := authority(t, tokens, 3, "events:list_all")
	w := call(handler, "GET", "/admin/events", "", list)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("empty admin listing: %d %s", w.Code, w.Body)
	}
	var want []events.Event
	for _, owner := range []int64{1, 2, 3} {
		w := call(handler, "POST", "/events", `{"type":"login.failed","source_ip":"192.0.2.1"}`, authority(t, tokens, owner, auth.AddEvent))
		var added events.Event
		if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &added) != nil {
			t.Fatalf("submit: %d %s", w.Code, w.Body)
		}
		want = append(want, added)
	}
	w = call(handler, "GET", "/admin/events", "", list)
	expected, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), expected) {
		t.Fatalf("admin listing: %d %s, want %s", w.Code, w.Body, expected)
	}
	for _, tt := range []struct{ path, body string }{
		{"/admin/events?owner_id=1", ""},
		{"/admin/events?limit=1", ""},
		{"/admin/events?%zz", ""},
		{"/admin/events", `{"owner_id":1}`},
	} {
		if w := call(handler, "GET", tt.path, tt.body, list); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid listing %s: status=%d", tt.path, w.Code)
		}
	}
	if after := call(handler, "GET", "/admin/events", "", list); !bytes.Equal(after.Body.Bytes(), expected) {
		t.Fatal("rejected requests changed stored events")
	}
}

func TestAdminEventsRejectOtherAuthority(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	handler := newRouter(&events.Store{}, tokens, public)
	unauthorized := []string{"", "not-a-jwt"}
	for _, action := range []string{auth.ListEvents, auth.AddEvent, auth.ListAlerts} {
		unauthorized = append(unauthorized, authority(t, tokens, 3, action))
	}
	userTokens, err := auth.New([]byte(strings.Repeat("u", 32)))
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []*auth.Tokens{userTokens, tokens} {
		raw, err := signer.Sign(auth.Identity{ID: 3, Role: "admin"})
		if err != nil {
			t.Fatal(err)
		}
		unauthorized = append(unauthorized, raw)
	}
	for _, tt := range []struct{ service, action string }{
		{auth.EventService, auth.ListEvents},
		{auth.EventService, auth.AddAlerts},
		{auth.DetectionService, auth.RunDetection},
	} {
		raw, err := auth.SignJob(private, 3, "job-1", tt.service, tt.action)
		if err != nil {
			t.Fatal(err)
		}
		unauthorized = append(unauthorized, raw)
	}
	// Supply even the correct job header; job authority still cannot list all events.
	for _, raw := range unauthorized {
		r := httptest.NewRequest("GET", "/admin/events", nil)
		r.Header.Set("Authorization", "Bearer "+raw)
		r.Header.Set(auth.JobHeader, "job-1")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("accepted unrelated authority: status=%d", w.Code)
		}
	}
}

func TestAdminEventsRejectInvalidDelegation(t *testing.T) {
	handler, _ := testHandler(t)
	for _, tt := range []struct {
		name   string
		change func(jwt.MapClaims)
		key    string
	}{
		{"forged", func(jwt.MapClaims) {}, strings.Repeat("x", 32)},
		{"user key", func(jwt.MapClaims) {}, strings.Repeat("u", 32)},
		{"expired", func(c jwt.MapClaims) { c["exp"] = time.Now().Add(-time.Minute).Unix() }, strings.Repeat("s", 32)},
		{"no expiry", func(c jwt.MapClaims) { delete(c, "exp") }, strings.Repeat("s", 32)},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = auth.DetectionService }, strings.Repeat("s", 32)},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "detection" }, strings.Repeat("s", 32)},
		{"missing principal", func(c jwt.MapClaims) { delete(c, "sub") }, strings.Repeat("s", 32)},
		{"wrong action", func(c jwt.MapClaims) { c["action"] = auth.ListEvents }, strings.Repeat("s", 32)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			claims := jwt.MapClaims{"iss": "mini-siem-api", "aud": auth.EventService, "sub": "3", "action": "events:list_all", "exp": time.Now().Add(30 * time.Second).Unix()}
			tt.change(claims)
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(tt.key))
			if err != nil {
				t.Fatal(err)
			}
			if w := call(handler, "GET", "/admin/events", "", raw); w.Code != http.StatusUnauthorized {
				t.Fatalf("invalid authority: status=%d", w.Code)
			}
		})
	}
}

func TestAdminEventsAuthorityCannotAccessOtherOperations(t *testing.T) {
	handler, tokens := testHandler(t)
	list := authority(t, tokens, 3, "events:list_all")
	for _, tt := range []struct{ method, path, body string }{
		{"POST", "/events", `{"type":"login.failed","source_ip":"192.0.2.1"}`},
		{"GET", "/events", ""},
		{"GET", "/alerts", ""},
		{"GET", "/jobs/events", ""},
		{"POST", "/jobs/alerts", `[{"source_ip":"192.0.2.1","detection_type":"failed_login_burst","failed_login_count":5}]`},
	} {
		if w := call(handler, tt.method, tt.path, tt.body, list); w.Code != http.StatusUnauthorized {
			t.Fatalf("privileged list authorized %s %s: status=%d", tt.method, tt.path, w.Code)
		}
	}
	for _, path := range []string{"/events", "/alerts"} {
		action := auth.ListEvents
		if path == "/alerts" {
			action = auth.ListAlerts
		}
		w := call(handler, "GET", path, "", authority(t, tokens, 3, action))
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
			t.Fatalf("rejected writes changed %s: %d %s", path, w.Code, w.Body)
		}
	}
}
