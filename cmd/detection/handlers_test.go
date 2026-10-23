package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/droggokid/mini-siem/eventkit"
	"github.com/droggokid/mini-siem/internal/auth"
)

func TestDetectionScopeAndValidation(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		fmt.Fprint(w, "[]")
	}))
	defer server.Close()
	handler := newRouter(server.URL, public)

	sign := func(owner int64, job, service, action string) string {
		t.Helper()
		token, err := auth.SignJob(private, owner, job, service, action)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	run := sign(1, "job-a", auth.DetectionService, auth.RunDetection)
	read := sign(1, "job-a", auth.EventService, auth.ListEvents)
	write := sign(1, "job-a", auth.EventService, auth.AddAlerts)
	body := func(read, write string) string {
		return fmt.Sprintf(`{"read_token":%q,"write_token":%q}`, read, write)
	}

	for _, tt := range []struct {
		name, path, body, token, job string
		status                       int
	}{
		{"direct", "/detections/run", body(read, write), "", "job-a", 401},
		{"event token", "/detections/run", body(read, write), read, "job-a", 401},
		{"wrong job header", "/detections/run", body(read, write), run, "job-b", 401},
		{"different read owner", "/detections/run", body(sign(2, "job-a", auth.EventService, auth.ListEvents), write), run, "job-a", 401},
		{"different write owner", "/detections/run", body(read, sign(2, "job-a", auth.EventService, auth.AddAlerts)), run, "job-a", 401},
		{"different read job", "/detections/run", body(sign(1, "job-b", auth.EventService, auth.ListEvents), write), run, "job-a", 401},
		{"different write job", "/detections/run", body(read, sign(1, "job-b", auth.EventService, auth.AddAlerts)), run, "job-a", 401},
		{"swapped actions", "/detections/run", body(write, read), run, "job-a", 401},
		{"missing capabilities", "/detections/run", `{}`, run, "job-a", 401},
		{"owner body", "/detections/run", `{"owner_id":2}`, run, "job-a", 400},
		{"owner query", "/detections/run?owner_id=2", body(read, write), run, "job-a", 400},
		{"null", "/detections/run", "null", run, "job-a", 400},
		{"trailing JSON", "/detections/run", body(read, write) + " {}", run, "job-a", 400},
		{"oversized", "/detections/run", strings.Repeat(" ", 65537), run, "job-a", 413},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tt.path, strings.NewReader(tt.body))
			r.Header.Set("Authorization", "Bearer "+tt.token)
			r.Header.Set(auth.JobHeader, tt.job)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tt.status {
				t.Fatalf("got %d %s, want %d", w.Code, w.Body, tt.status)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached Event")
	}
}

func TestDetectionWorkflowAndUpstreamFailures(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	run, _ := auth.SignJob(private, 1, "job-a", auth.DetectionService, auth.RunDetection)
	read, _ := auth.SignJob(private, 1, "job-a", auth.EventService, auth.ListEvents)
	write, _ := auth.SignJob(private, 1, "job-a", auth.EventService, auth.AddAlerts)

	for _, mode := range []string{"success", "empty", "read failure", "malformed", "wrong owner", "write failure", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(auth.JobHeader) != "job-a" {
					t.Error("missing job scope")
				}
				if r.Method == "POST" {
					writes++
					if r.URL.Path != "/jobs/alerts" || r.Header.Get("Authorization") != "Bearer "+write {
						t.Error("wrong write authority")
					}
					var alerts []eventkit.Finding
					if json.NewDecoder(r.Body).Decode(&alerts) != nil || len(alerts) != 1 || alerts[0].FailedLoginCount != 5 {
						t.Error("incorrect findings")
					}
					if mode == "write failure" {
						w.WriteHeader(500)
						return
					}
					w.WriteHeader(201)
					fmt.Fprint(w, `{"alerts_created":1}`)
					return
				}

				if r.URL.Path != "/jobs/events" || r.Header.Get("Authorization") != "Bearer "+read {
					t.Error("wrong read authority")
				}
				switch mode {
				case "empty":
					fmt.Fprint(w, "[]")
				case "read failure":
					w.WriteHeader(401)
				case "redirect":
					w.Header().Set("Location", "/steal-token")
					w.WriteHeader(307)
				case "malformed":
					fmt.Fprint(w, "invalid JSON")
				default:
					owner := 1
					if mode == "wrong owner" {
						owner = 2
					}
					item := fmt.Sprintf(`{"owner_id":%d,"type":"login.failed","source_ip":"192.0.2.1","ingested_at":"2020-01-01T00:00:00Z"}`, owner)
					fmt.Fprint(w, "["+strings.TrimSuffix(strings.Repeat(item+",", 5), ",")+"]")
				}
			}))
			defer server.Close()

			r := httptest.NewRequest("POST", "/detections/run", strings.NewReader(fmt.Sprintf(`{"read_token":%q,"write_token":%q}`, read, write)))
			r.Header.Set("Authorization", "Bearer "+run)
			r.Header.Set(auth.JobHeader, "job-a")
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			newRouter(server.URL, public).ServeHTTP(w, r)
			want := 502
			if mode == "success" || mode == "empty" {
				want = 200
			}
			if w.Code != want {
				t.Fatalf("got %d %s want %d", w.Code, w.Body, want)
			}
			if mode != "success" && mode != "write failure" && writes != 0 {
				t.Fatal("wrote alerts after invalid/empty fetch")
			}
			if mode == "success" && (writes != 1 || !strings.Contains(w.Body.String(), `"alerts_created":1`)) {
				t.Fatal("missing alerts/summary")
			}
		})
	}
}
