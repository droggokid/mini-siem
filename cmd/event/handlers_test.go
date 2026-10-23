package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/droggokid/mini-siem/cmd/event/internal/events"
	"github.com/droggokid/mini-siem/internal/auth"
	"github.com/golang-jwt/jwt/v5"
)

func testHandler(t *testing.T) (http.Handler, *auth.Tokens) {
	t.Helper()
	tokens, err := auth.New([]byte(strings.Repeat("s", 32)))
	if err != nil {
		t.Fatal(err)
	}
	return newRouter(&events.Store{}, tokens), tokens
}

func call(handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func authority(t *testing.T, tokens *auth.Tokens, owner int64, action string) string {
	t.Helper()
	raw, err := tokens.SignEvent(owner, action)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRejectDirectUnauthorizedRequests(t *testing.T) {
	handler, tokens := testHandler(t)
	for _, tt := range []struct {
		name, issuer, audience, action, subject, key string
		expiry                                       time.Time
	}{
		{"forged", "mini-siem-api", "mini-siem-event", auth.AddEvent, "1", strings.Repeat("x", 32), time.Now().Add(time.Minute)},
		{"expired", "mini-siem-api", "mini-siem-event", auth.AddEvent, "1", strings.Repeat("s", 32), time.Now().Add(-time.Minute)},
		{"user JWT", "mini-siem", "mini-siem-api", "", "1", strings.Repeat("u", 32), time.Now().Add(time.Minute)},
		{"wrong service", "mini-siem-api", "mini-siem-detection", auth.AddEvent, "1", strings.Repeat("s", 32), time.Now().Add(time.Minute)},
		{"wrong action", "mini-siem-api", "mini-siem-event", "events:all", "1", strings.Repeat("s", 32), time.Now().Add(time.Minute)},
		{"missing owner", "mini-siem-api", "mini-siem-event", auth.AddEvent, "", strings.Repeat("s", 32), time.Now().Add(time.Minute)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"iss": tt.issuer, "aud": tt.audience, "action": tt.action, "sub": tt.subject, "exp": tt.expiry.Unix(),
			}).SignedString([]byte(tt.key))
			if err != nil {
				t.Fatal(err)
			}
			for _, method := range []string{"POST", "GET"} {
				if w := call(handler, method, "/events", `{"type":"login.failed","source_ip":"192.0.2.1"}`, raw); w.Code != http.StatusUnauthorized {
					t.Fatalf("%s status=%d, want 401", method, w.Code)
				}
			}
		})
	}
	for _, method := range []string{"POST", "GET"} {
		for _, raw := range []string{"", "not-a-token"} {
			if w := call(handler, method, "/events", "", raw); w.Code != http.StatusUnauthorized {
				t.Fatalf("missing/invalid token status=%d", w.Code)
			}
		}
	}
	for _, tt := range []struct{ method, action string }{{"POST", auth.ListEvents}, {"GET", auth.AddEvent}} {
		if w := call(handler, tt.method, "/events", "", authority(t, tokens, 1, tt.action)); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong action status=%d", w.Code)
		}
	}
	r := httptest.NewRequest("GET", "/events", nil)
	r.Header.Add("Authorization", "Bearer "+authority(t, tokens, 1, auth.ListEvents))
	r.Header.Add("Authorization", "Bearer forged")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("accepted multiple Authorization headers")
	}
	w = call(handler, "GET", "/events", "", authority(t, tokens, 1, auth.ListEvents))
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("unauthorized requests changed store: %d %s", w.Code, w.Body)
	}
}

func TestValidateRequests(t *testing.T) {
	handler, tokens := testHandler(t)
	add := authority(t, tokens, 1, auth.AddEvent)
	for _, body := range []string{"", "{", "null", "[]", `{}`, `{"type":"login.failed"}`, `{"type":3,"source_ip":"192.0.2.1"}`, `{"type":"login.failed","source_ip":"999.999.999.999"}`, `{"type":"login.failed","source_ip":"192.0.2.1","owner_id":2}`, `{"type":"login.failed","source_ip":"192.0.2.1","id":"chosen"}`, `{"type":"login.failed","source_ip":"192.0.2.1","ingested_at":"2026-01-01T00:00:00Z"}`, `{"type":"login.failed","source_ip":"192.0.2.1"} {}`, `{"type":"login.failed","source_ip":"192.0.2.1"} garbage`} {
		if w := call(handler, "POST", "/events", body, add); w.Code != http.StatusBadRequest {
			t.Fatalf("body=%q status=%d, want 400", body, w.Code)
		}
	}
	list := authority(t, tokens, 1, auth.ListEvents)
	w := call(handler, "GET", "/events", "", list)
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("malformed requests stored events: %s", w.Body)
	}
	valid := `{"type":"login.failed","source_ip":"192.0.2.1"}`
	for _, size := range []int{64 * 1024, 64*1024 + 1} {
		want := http.StatusCreated
		if size > 64*1024 {
			want = http.StatusRequestEntityTooLarge
		}
		if w := call(handler, "POST", "/events", valid+strings.Repeat(" ", size-len(valid)), add); w.Code != want {
			t.Fatalf("body size=%d status=%d, want %d", size, w.Code, want)
		}
	}
	r := httptest.NewRequest("POST", "/events", strings.NewReader(valid))
	r.Header.Set("Authorization", "Bearer "+add)
	r.Header.Set("Content-Type", "text/plain")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported media status=%d", w.Code)
	}
	for _, tt := range []struct {
		body string
		want int
	}{{"{}", http.StatusBadRequest}, {strings.Repeat("x", 64*1024+1), http.StatusRequestEntityTooLarge}} {
		if w := call(handler, "GET", "/events", tt.body, list); w.Code != tt.want {
			t.Fatalf("GET body status=%d, want %d", w.Code, tt.want)
		}
	}
	if w := call(handler, "GET", "/events?owner_id=2", "", list); w.Code != http.StatusBadRequest {
		t.Fatal("accepted caller-selected owner query")
	}
	w = call(handler, "GET", "/events", "", list)
	var stored []events.Event
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil || len(stored) != 1 {
		t.Fatalf("stored invalid events: %s", w.Body)
	}
}

func TestSubmitAndListByVerifiedOwner(t *testing.T) {
	handler, tokens := testHandler(t)
	for _, owner := range []int64{1, 2} {
		body := fmt.Sprintf(`{"type":"login.failed","source_ip":"192.0.2.%d"}`, owner)
		before := time.Now()
		w := call(handler, "POST", "/events", body, authority(t, tokens, owner, auth.AddEvent))
		if w.Code != http.StatusCreated {
			t.Fatalf("submit status=%d body=%s", w.Code, w.Body)
		}
		var added events.Event
		if err := json.Unmarshal(w.Body.Bytes(), &added); err != nil {
			t.Fatal(err)
		}
		if added.ID == "" || added.OwnerID != owner || added.IngestedAt.Before(before) || added.IngestedAt.After(time.Now()) {
			t.Fatalf("incorrect Event metadata: %+v", added)
		}
	}
	for _, owner := range []int64{1, 2, 3} {
		w := call(handler, "GET", "/events", "", authority(t, tokens, owner, auth.ListEvents))
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("list status=%d headers=%v", w.Code, w.Header())
		}
		var got []events.Event
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		want := 1
		if owner == 3 {
			want = 0
		}
		if len(got) != want {
			t.Fatalf("owner %d got %d events, want %d", owner, len(got), want)
		}
		for _, event := range got {
			if event.OwnerID != owner || event.Type != "login.failed" || event.SourceIP != fmt.Sprintf("192.0.2.%d", owner) {
				t.Fatalf("owner %d received another owner's event: %+v", owner, event)
			}
		}
	}
	if w := call(handler, "GET", "/health", "", ""); w.Code != http.StatusOK || w.Body.String() != "ok\n" {
		t.Fatal("health endpoint changed")
	}
}

func TestConcurrentEventSubmissions(t *testing.T) {
	handler, tokens := testHandler(t)
	const workers, submissions = 8, 10
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := range workers {
		owner := int64(worker%2 + 1)
		add := authority(t, tokens, owner, auth.AddEvent)
		list := authority(t, tokens, owner, auth.ListEvents)
		wg.Go(func() {
			<-start
			for range submissions {
				if w := call(handler, "POST", "/events", `{"type":"login.failed","source_ip":"192.0.2.1"}`, add); w.Code != http.StatusCreated {
					t.Errorf("concurrent submit status=%d body=%s", w.Code, w.Body)
				}
				if w := call(handler, "GET", "/events", "", list); w.Code != http.StatusOK {
					t.Errorf("concurrent list status=%d", w.Code)
				}
			}
		})
	}
	close(start)
	wg.Wait()
	ids := make(map[string]bool)
	for _, owner := range []int64{1, 2} {
		w := call(handler, "GET", "/events", "", authority(t, tokens, owner, auth.ListEvents))
		var got []events.Event
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != workers*submissions/2 {
			t.Fatalf("owner %d received %d events: %v", owner, len(got), err)
		}
		for _, event := range got {
			if event.OwnerID != owner || event.ID == "" || ids[event.ID] {
				t.Fatalf("incorrect owner or event ID: %+v", event)
			}
			ids[event.ID] = true
		}
	}
}
