package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/droggokid/mini-siem/cmd/event/internal/events"
	"github.com/droggokid/mini-siem/internal/auth"
)

func TestJobEventAndAlertPermissions(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	tokens, _ := auth.New([]byte(strings.Repeat("s", 32)))
	var store events.Store
	store.Add(1, "login.failed", "192.0.2.1")
	store.Add(2, "login.failed", "192.0.2.2")
	handler := newRouter(&store, tokens, public)
	read, _ := auth.SignJob(private, 1, "job-a", auth.EventService, auth.ListEvents)
	write, _ := auth.SignJob(private, 1, "job-a", auth.EventService, auth.AddAlerts)
	run, _ := auth.SignJob(private, 1, "job-a", auth.DetectionService, auth.RunDetection)
	valid := `[{"source_ip":"192.0.2.1","detection_type":"failed_login_burst","failed_login_count":5}]`
	for _, tt := range []struct {
		method, path, body, token, job string
		status                         int
	}{
		{"GET", "/jobs/events", "", read, "job-a", 200},
		{"GET", "/jobs/events?owner_id=2", "", read, "job-a", 400},
		{"GET", "/jobs/events", "{}", read, "job-a", 400},
		{"GET", "/jobs/events", strings.Repeat(" ", 65537), read, "job-a", 413},
		{"GET", "/jobs/events", "", read, "job-b", 401},
		{"GET", "/jobs/events", "", write, "job-a", 401},
		{"GET", "/jobs/events", "", run, "job-a", 401},
		{"POST", "/jobs/alerts", valid, "", "job-a", 401},
		{"POST", "/jobs/alerts", valid, read, "job-a", 401},
		{"POST", "/jobs/alerts", valid, write, "job-b", 401},
		{"POST", "/jobs/alerts", `[{"owner_id":2}]`, write, "job-a", 400},
		{"POST", "/jobs/alerts", "null", write, "job-a", 400},
		{"POST", "/jobs/alerts", "{}", write, "job-a", 400},
		{"POST", "/jobs/alerts", valid + " {}", write, "job-a", 400},
		{"POST", "/jobs/alerts", strings.Repeat(" ", 65537), write, "job-a", 413},
		{"POST", "/jobs/alerts?owner_id=2", valid, write, "job-a", 400},
		{"GET", "/alerts", "", read, "job-a", 401},
		{"POST", "/events", `{"type":"login.failed","source_ip":"192.0.2.1"}`, write, "job-a", 401},
		{"POST", "/jobs/alerts", valid, write, "job-a", 201},
	} {
		r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
		r.Header.Set("Authorization", "Bearer "+tt.token)
		r.Header.Set(auth.JobHeader, tt.job)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tt.status {
			t.Fatalf("%s %s got %d %s want %d", tt.method, tt.path, w.Code, w.Body, tt.status)
		}
		if tt.path == "/jobs/events" && w.Code == 200 && strings.Contains(w.Body.String(), "192.0.2.2") {
			t.Fatal("read leaked Bob event")
		}
	}
	for _, owner := range []int64{1, 2, 3} {
		w := call(handler, "GET", "/alerts", "", authority(t, tokens, owner, auth.ListAlerts))
		if w.Code != 200 {
			t.Fatalf("list: %d %s", w.Code, w.Body)
		}
		if owner != 1 && w.Body.String() != "[]" {
			t.Fatalf("owner %d saw %s", owner, w.Body)
		}
	}
	if len(store.ListAlerts(1)) != 1 || len(store.ListAlerts(2)) != 0 {
		t.Fatal("wrong alert ownership/count")
	}
}
